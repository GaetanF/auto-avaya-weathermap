#!/usr/bin/perl

require 'Avaya.pm';
require '/etc/centreon/conf.pm';

use Net::SNMP;
use Getopt::Long;
use Data::Dumper;
use Avaya qw(%AvayaModel);
use Array::Utils qw(:all);
use DBI;
use POSIX;
use Storable;

use vars qw(%snmp_sessions %Models @ipParents $rocommunity %Topology $strMap %mapper @alreadyLinked $maxDepth $weathermapName $mibOid $sysDescOid $sysNameOid $ipAddrOid $nbrParents %allIps $checkWarningPct $checkCriticalPct $dryrun $dbhCentreon $dbhCentstorage $mapId $nbrTotalLinks $onlyCentreon $onlyWeathermap %modelsOid);

#**
#   SNMP Specific OID variables
#*
$mibOid="1.3.6.1.4.1.45.1.6.13.2.1.1";
$sysDescOid="1.3.6.1.2.1.1.1.0";
$sysNameOid="1.3.6.1.2.1.1.5.0";
$ipAddrOid="1.3.6.1.2.1.4.20.1.1";

#**
#   WeatherMap Specific variables
#*
$width=4000;
$height=3000;
$dftOffVert=30;
$dftOffHort=40;
$hBoxPar=100;
$wBoxPar=200;

#**
#   WeatherMap Specific variables
#*
$loginCentreon="admin";
$pwdCentreon="PwdAdminCentreon";
$pathClapi="/usr/share/centreon/www/modules/centreon-clapi/core/centreon";
$pathCfgWeathermap="/usr/share/centreon/www/modules/php-weathermap/configuration/editor/configs";
$pathMetrics="/var/lib/centreon/metrics";
$dftTemplate="Switchs-NORTEL";
$dftHostGroup="Avaya";
$dftPoller="Central";
$checkWarningPct=80;
$checkCriticalPct=90;

#** @method usage($rc);
#   Show usage command
#   
#   @param $rc  return code
#* 
sub usage {
   my( $rc ) = @_;
   print "Usage: $0 [-dvh] -H <host> -C <community> -N <mapName>
       -H s  ip of core switch (172.20.1.1 or 192.168.0.1;192.168.0.2)
       -C s  snmp community [public]
       -N s  weathermap name
       -d    dry run
       -v    verbose
       -h    help\n";
   exit $rc;
}

#** @method writeMap($mapContent)
#   Add content to wheatermap file
#  
#   @param  $mapContent  string added to the content of the weathermap file
#* 
sub writeMap {
    my ($mapContent) = @_;
    $strMap=$strMap.$mapContent; 
}

#** @method commitMap()
#   Write weathermap to file
#*
sub commitMap {
    open (STARTMAP, "<startMap");
    open (MYMAPFILE, ">".$pathCfgWeathermap."/".$weathermapName);
    while (<STARTMAP>) {
        print MYMAPFILE $_; 
    }
    print MYMAPFILE "\n";
    print MYMAPFILE $strMap;
    close(MYMAPFILE);
}

#** @method snmp_get_one($dev,$community,$name,$oid)
#   Get one snmp value from a device
#
#   @param  $dev        ip device
#   @param  $community  snmp community
#   @param  $name       name of the device
#   @param  $oid        snmp oid
#   @retval value of the oid
#* 
sub snmp_get_one {
    my( $dev, $community, $name, $oid ) = @_;
    my( $session, @oids, $result, $oid2, $val );

    $verbose && print "snmp_get $dev $name\n";
    $session = snmp_session( $dev, $community );
    @oids = ( $oid );
    $result = $session->get_request( -varbindlist => \@oids );
    if ( ! defined( $result ) ) {
        #warn sprintf "error getting %s from %s: %s\n",
        #    $name, $session->hostname, $session->error();
        return undef;
    }

    if ( ! exists $result->{ $oid } ) {
        #warn "snmp_get error: requested $name oid $oid not in response\n";
        return undef;
    }
    return $result->{ $oid };
}

#** @method snmp_session($ip,$community)
#   Open and store snmp session
#
#   @param  $ip         ip of a device
#   @param  $community  snmp community
#   @retval snmp session
#* 
sub snmp_session {
    my( $dev, $community ) = @_;
    my( $ip, $session, $error );

    if ( $dev =~ m/^\d[\d\.]+$/ ) {
        $ip = $dev;
        }
    else {
        $ip = name2ip( $dev );
        if ( ! $ip ) {
            print "unable to resolve $dev to an ip\n";
            return undef;
            }
        }

    if ( exists $snmp_sessions{ "$ip,$community" } ) {
        return $snmp_sessions{ "$ip,$community" };
        }

    ( $session, $error ) = Net::SNMP->session(
        -version => $use_snmpv2c ? 'snmpv2c' : 'snmpv1',
        -hostname => $ip,
        -community => $community,
        -timeout => 5.0,
        -retries => 3,
        -port => 161
        #-debug => 0x02
    );
    if ( ! defined( $session ) ) {
        push @unknowns, "snmp setup error: $error\n";
        return undef;
    }
    $session->translate( [ '-octetstring' => 0 ] );
    $snmp_sessions{ "$ip,$community" } = $session;
    return $session;
}

#** @method name2ip($name)
#   Get ip address of a fqdn
#
#   @param  $name  FQDN
#   @retval ip resolution of the fqdn
#* 
sub name2ip {
    my( $name ) = @_;
    my( $ip, $a, $b, $c, $d );

    if ( defined( $name2ip{ $name } ) ) {
        $ip = $name2ip{ $name };
        }
    elsif ( $name =~ m/^\s*(\d+\.\d+\.\d+\.\d+)\s*$/ ) {
        $ip = $1;
        $name2ip{ $name } = $ip;
        $name2ip{ $1 } = $ip;
        }
    else {
        $ip = gethostbyname( $name );
        if ( ! $ip ) {
            return undef;
            }
        ($a,$b,$c,$d) = unpack( 'C4', $ip );
        $ip = "$a.$b.$c.$d";
        $name2ip{ $name } = $ip;
        }
    return $ip;
}

#** @method walk_table2($dev,$community,$name,$baseoid)
#   Walk table from snmp with processing
#   @param  $dev        ip device
#   @param  $community  snmp community v2
#   @param  $name       device name
#   @param  $baseoid    base oid
#   @retval array of data
#*
sub walk_table2 {
    my( $dev, $community, $name, $baseoid ) = @_;
    my( $result, %rows, $nrows, $oid, $val, $col, $row, @data );

    $verbose && print "walk_table2 $dev $name\n";

    $result = snmp_walk( $dev, $community, $name, $baseoid ) || return undef;

    foreach $oid ( keys %$result ) {
        $val = $result->{ $oid };
        $verbose > 1 && print "$oid = $val\n";
        next if ( $val eq 'endOfMibView' );
        if ( $oid =~ m/$baseoid\.(\d+)\.([\d\.]+)$/ ) {
            $col = $1; $row = $2;
            $rows{ $row } = 1;
            $data[$col]{$row} = $val;
            }
        }

    $nrows = scalar keys %rows;
    if ( ! $nrows ) {
        push @unknowns, "no rows in $name table on $dev";
        return undef;
        }

    return @data;
}

#** @method snmp_walk($dev,$community,$name,$baseoid)
#   Walk table from snmp without processing
#   @param  $dev        ip device
#   @param  $community  snmp community v2
#   @param  $name       device name
#   @param  $baseoid    base oid
#   @retval result of snmp walk
#*
sub snmp_walk {
    my( $dev, $community, $name, $baseoid ) = @_;
    my( $session, $result );

    $verbose && print "snmp_walk $dev $name\n";

    $session = snmp_session( $dev, $community );
    if ( ! defined( $session ) ) {
        return undef;
    }
    $result = $session->get_table( -baseoid => $baseoid );
    #print "session error ", $session->error(), "\n";
    if ( ! defined( $result )
       && $session->error() !~ m/Requested table is empty/ ) {
        #warn sprintf( "error walking $name table on %s: %s",
        #$session->hostname, $session->error() );
        #push @unknowns, sprintf( "error walking $name table on %s: %s",
        #$session->hostname, $session->error() );
        return undef;
    }
    return $result;
}

#** @method getName($dev)
#   Get name of a device via snmp
#
#   @param  $dev  ip device
#   @retval name of the device
#*
sub getName {
    my ( $dev ) = @_;
    my $name = snmp_get_one($dev, $rocommunity, $dev, $sysNameOid);
    $name =~ s/ /_/g;
    if(!$name) {
        $name=$dev;
        $name =~ s/\./_/g;
    }
    return $name;
}

#** @method getAllIps($ipGet)
#   Get all ip address of a device
#   
#   @param  $ipGet  ip device to fetch
#*
sub getAllIps {
    my ( $ipGet ) = @_;
    my ($key,$ip,%addrIp,$ipFin);
    %addrIp = %{snmp_walk($ipGet, $rocommunity, $ipGet, $ipAddrOid)};
    $ipFin=$ipGet;
    while(($key,$ip)=each %addrIp) {
        if(grep /^$ip$/, @ipParents) {
            $ipFin=$ip;
        }
    }
    while (($key,$ip)=each %addrIp) {
        if(!grep /^$ip$/, keys %allIps) {
            $allIps{$ip} = $ipFin;
        }
    }
}

#** @method checkIP($IPCheck)
#   Check if IP already exist in topology
#   
#   @param  $IPCheck  ip of existent or current device
#*
sub checkIP {
    my ( $IPCheck ) = @_;
    if($allIps{$IPCheck}){
        return $allIps{$IPCheck};
    }
    return $IPCheck;
}

#** @method fetchDevice($dev)
#   Use SNMP and Nortel Topology Oid to fetch all subdevice of an equipment
#
#   @param  $dev  ip of device
#*
sub fetchDevice {
    my( $dev ) = @_;
    my( $ip, $port, $int, $x, @aTopo,$key,$value,$modelId,$name,$slot,$if,$model,$oid);

    @aTopo = walk_table2($dev,$rocommunity,$dev,$mibOid);
    $x = @aTopo[4];
    while (($key, $value) = each %$x)
    {
        if( $value != 0 && $key =~ /([0-9]).([0-9]{0,2}).172.([0-9]{0,3}).([0-9]{0,3}).([0-9]{0,3}).([0-9]*)/ ) {
            $ip = "172.$3.$4.$5";
            $ip = checkIP($ip);
            $oid = snmp_get_one($ip,$rocommunity,$ip,"1.3.6.1.2.1.1.2.0");
            if( defined @aTopo[6] ) {
                $modelId=${@aTopo[6]}{$key};
                $model=$AvayaModel{$modelId}{"model"};
                $modelsOid{$oid}=$model;
            }
        }
    }
    while (($key, $value) = each %$x)
    {
        if( $value != 0 && $key =~ /([0-9]).([0-9]{0,2}).172.([0-9]{0,3}).([0-9]{0,3}).([0-9]{0,3}).([0-9]*)/ ) {
            $ip = "172.$3.$4.$5";
            $slot=$1;
            $if=$2;
            $port = "$slot/$if";
            $model="";
            if( defined @aTopo[6] ) {
                $modelId=${@aTopo[6]}{$key};
                print $modelId;
                if( $modelId != '' && ! grep( /^$ip$/, @{$Models{$AvayaModel{$modelId}{"model"}}} ) ) {
                    push(@{$Models{$AvayaModel{$modelId}{"model"}}}, $ip);
                }
            }
            $model = $modelsOid{snmp_get_one($dev,$rocommunity,$dev,"1.3.6.1.2.1.1.2.0")};
            print $model."\n";
            if( $model =~ m/mPassport[0-9]*/ || $model =~ m/mERS88[0-9]*/ ) {
                $int = $slot * 64 + ($if) - 1;
            } elsif( $model =~ m/mERS55.*/ ) {
                $int = ($slot-1) * 128 + $if
            } else {
                $int = ($slot-1) * 64 + $if;
            }
            getAllIps($ip);
            $ip = checkIP($ip);
            $Topology{$dev}{"children"}{$int}{"ip"} = $ip;
            $Topology{$dev}{"children"}{$int}{"port"} = $port;
            if(!exists($Topology{$ip}) ){
                $name = getName($ip);
                $Topology{$ip} = {"firstParent"=>0,"name"=>$name,"children"=>()};
                fetchDevice($ip);
            }
        }
    }
}

#** @method getNbrMutual()
#   Get number of devices are on both coreswitch
#   
#   @retval number of devices
#*
sub getNbrMutual {
    my ($i,$key,$ip,$ipParent,@tab,@intsct,%hash);
    $i=0;
    $return=1;
    @tab=();
    foreach $ipParent (@ipParents) {
        %hash = %{ $Topology{$ipParent}{children} };
        foreach $key (keys %hash) {
            $ip = $hash{$key}{"ip"};
            if( ! grep(/^$ip$/, @{$tab[$i]}) && ! grep(/^$ip$/, @ipParents) ) {
                push(@{$tab[$i]}, $ip);
            }
        }
        $i++;
    }
    if($i == 1)
    {
        my @tmp = @ipParents;
        $ipParent = shift(@tmp);
        $return = getNbrChild($ipParent); 
    }else{
        @intsct = intersect(@{$tab[0]}, @{$tab[1]});
        $return = $#intsct + 1;
    }
    return $return;
}

#** @method getRecurseDepth($curDepth,$dev)
#   Recursivity function
#   Get depth of all equipment of the topology
#
#   @param  $curDepth  current depth
#   @param  $dev       ip of device to process
#*
sub getRecurseDepth {
    my ($curDepth, $dev) = @_;
    my ($key,$ip,%hash);
    %hash = %{ $Topology{$dev}{children} };
    if(%hash) {
        foreach $key (keys %hash) {
            $ip = $hash{$key}{ip};
            if(!exists($allDepths{$ip})){
                $allDepths{$ip}=$curDepth+1;
                getRecurseDepth($curDepth+1, $ip);
            }
        }
    }
}

#** @method getTopologyDepth()
#   Get depth of all equipment of the topology
#*
sub getTopologyDepth {
    my ($ipParent,$depth);
    $maxDepth=0;
    foreach $ipParent (@ipParents) {
        $allDepths{$ipParent}=0;
    }
    foreach $ipParent (@ipParents) {
        getRecurseDepth(0, $ipParent);
    }
    foreach $depth ( values %allDepths ) {
        if($depth > $maxDepth) {
            $maxDepth = $depth;      
        }
    } 
}

#** @method getParent($child)
#   Get IP Parent of a device
#
#   @param  $child  ip of a device
#   @retval ip of the parent
#*
sub getParent {
    my ($child) = @_;
    my ($key,$myDepth,$ip,%hash);
    $myDepth = $allDepths{$child};
    %hash = %{ $Topology{$child}{children} };
    foreach $key (keys %hash ) {
        $ip = $hash{$key}{ip};
        if( $allDepths{$ip} == ($myDepth-1) ) {
            return $ip;
        }
    }
}

#** @method getAllParentsNameCentreon($child)
#   Get Centreon CLAPI Parent representation of a device
#
#   @param  $child  child ip device
#   @retval parents string representation
#*
sub getAllParentsNameCentreon {
    my ($child) = @_;
    my ($key,$myDepth,$ip,%hash,@arrPar);
    $myDepth = $allDepths{$child};
    %hash = %{ $Topology{$child}{children} };
    if(%hash){
        foreach $key (keys %hash ) {
            $ip = $hash{$key}{ip};
            if( $allDepths{$ip} == ($myDepth-1) ) {
                push(@arrPar, $Topology{$ip}{name});
            }
        }
    }
    if(($myDepth-1) == 0 && $#arrPar == -1) {
        foreach $ip (@ipParents) {
            push(@arrPar, $Topology{$ip}{name});
        }
    }
    return join("|",@arrPar);
}

#** @method getChild($par)
#   Get children equipment of a device
#
#   @param  $par  parent ip
#   @retval array of child ip
#*
sub getChild {
    my ($par) = @_;
    my ($myDepth,$key,$ip,@arr,%hash);
    $myDepth = $allDepths{$par};
    %hash = %{ $Topology{$par}{children} };
    @arr;
    foreach $key (keys %hash) {
        $ip = $hash{$key}{ip};
        if( $allDepths{$ip} == ($myDepth+1) ) {
            push(@arr, $ip);
        }
    }
    return @arr;
}

#** @method getNbrLinksParents()
#   Get number of links between 2 coreswitch
#
#   @retval number of links
#*
sub getNbrLinksParents {
    my ($nbrLinks,$par0,$par1,%hash,$key,$ip);
    $nbrLinks=0;
    if($nbrParents == 2 ) {
       $par0=$ipParents[0];
       $par1=$ipParents[1];
       %hash = %{ $Topology{$par0}{children} };
       foreach $key (keys %hash ) {
           $ip=$hash{$key}{ip};
           if($ip eq $par1) {
               $nbrLinks++;
           }
       } 
    }
    return $nbrLinks;
}

#** @method getNbrChild($parent)
#   Get number of child equipment of a device
#
#   @retval number of child equipment
#*
sub getNbrChild {
    my ($parent) = @_;
    my @arr;
    @arr = getChild($parent);
    if(@arr){
        return $#arr;
    }else{
        return 0;
    }
}

#** @method getNbrParents()
#   Get number of coreswitch
#   
#   @retval number of coreswitch
#*
sub getNbrParents {
    my $nb = @ipParents;
    $nbrParents = $nb;
    return $nbrParents;
}

#** @method calculateCoordinatesMap()
#   Calculate coordinates of all equipment
#   If topology have more than two coreswitch, positionning equipment
#   using row else if topology have one coreswitch, positionning equipment
#   using polar coordinates
#*
sub calculateCoordinatesMap {
    my ($x,$y,$col,$deltaX,$deltaY,$j,$i,$line,$myLine,$linPar,$colPar);
    my ($ipParent,$indPrt,$key,$depth,$nbrChild,$ip,$nbrMutual,$nbrParents);
    $x=$y=$i=$col=$indPrt=0;
    $nbrMutual = getNbrMutual;
    $nbrParents = getNbrParents;
    $deltaY=floor($height/(1+2*$maxDepth));
    $deltaX=floor($width/(ceil($nbrMutual / 2)));

    foreach my $ipParent ( @ipParents ) {
        $y=$height/2 - 10;
        $x=$width/2;
        if($nbrParents > 1 ) {
            if($indPrt==0){
                $x=$x-200;
            }elsif($indPrt==1){
                $x=$x+200;
            }
            $indPrt++;
        }
        $mapper{$ipParent}{x}=$x;
        $mapper{$ipParent}{y}=$y;
    }

    for( $i=1; $i<=$maxDepth; $i++ ) {
        $j=0;
        $col=0;
        while(($key,$depth) = each(%allDepths)) {
            $line=$i;
            if( $j >= ceil($nbrMutual / 2) ) {
                $line=-1*$i;
            }
            if($depth == $i && $i == 1) {
                if ($j == ceil($nbrMutual / 2) ) {
                    $col=0;
                }
                $mapper{$key}{x}=$col*$deltaX + 100;
                $mapper{$key}{c}=$col;
                $mapper{$key}{y}=floor(($height/2)+$line*$deltaY);
                $mapper{$key}{l}=$line;
                $mapper{$key}{nbrChildPlaced}=0;
                $col++; 
                $j++;
            }elsif( $depth == $i && $i > 1 ) {
                $ip=getParent($key);
                $colPar=$mapper{$ip}{c};
                $linPar=$mapper{$ip}{l};
                $nbrChild=getNbrChild($ip);
                if($nbrChild>0){
                    $myDeltaX=floor($deltaX/(($depth-1)*($nbrChild+1)));
                }else{
                    $myDeltaX=$deltaX;
                }
                if($linPar > 0) {
                    $myLine=$linPar+1;
                }else{
                    $myLine=$linPar-1;
                }
                $mapper{$key}{x}=$colPar*$deltaX + 25 + $myDeltaX*$mapper{$ip}{nbrChildPlaced};
                $mapper{$key}{y}=($height/2)+$myLine*$deltaY;
                $mapper{$key}{l}=$myLine;
                $mapper{$key}{c}=$colPar + $mapper{$ip}{nbrChildPlaced}/($nbrChild+1);
                $mapper{$ip}{nbrChildPlaced}++;
                $j++;
            }
        }
    }
}

#** @method getHostID($name)
#   Get Host Centreon ID
#
#   @param  $name   name of host
#   @retval host id
#*
sub createWeathermap {
    my ($query,$prep);
    $query = "INSERT INTO pwm_maps (pwm_name, pwm_alias, pwm_comment) VALUES ( ?, ?, ?)";
    $prep = $dbhCentreon->prepare($query) or die $dbhCentreon->errstr; 
    $prep->execute($weathermapName,$weathermapName,$weathermapName) or die "Error query : $query\n"; 
    $prep->finish(); 

    $query = "SELECT MAX(pwm_id) FROM pwm_maps WHERE pwm_name = ? LIMIT 1";
    $prep = $dbhCentreon->prepare($query) or die $dbhCentreon->errstr; 
    $prep->execute($weathermapName) or die "Error query : $query\n"; 
    ($mapId) = $prep->fetchrow_array;
}

#** @method getCentreonHostID($name)
#   Get Host Centreon ID
#
#   @param  $name   name of host
#   @retval host id
#*
sub getCentreonHostID {
    my ($name) = @_;
    my ($query,$data,$svc_id,%traffic,$metric,$allServices);
    $allHosts = centreonCommand("HOST","SHOW","");
    $allHosts =~ /([0-9]*);$name;.*/s;
    $host_id=$1;
    return $host_id;
}

#** @method getCentreonServiceID($name,$port)
#   Get Service Centreon ID
#
#   @param  $name   Name of host
#   @param  $port   Port of host
#   @retval service id
#*
sub getCentreonServiceID {
    my ($name,$port) = @_;
    my ($svc_id,$allServices);
    $allServices = centreonCommand("SERVICE","SHOW","");
    $allServices =~ /[0-9]*;$name;([0-9]*);If-$port;.*/s;
    $svc_id=$1;
    return $svc_id;
}
#** @method insertNodeIntoWeatherMap($name)
#   Insert node into weathermap database configuration
#
#   @param  $name  Name of device
#*
sub insertNodeIntoWeatherMap {
    my ($name) = @_;
    my ($query,$prep);
    $query = "INSERT INTO pwm_host_node_relation (host_host_id, pwm_map_id, node_id) VALUES ( ?, ?, ?)";
    $prep = $dbhCentreon->prepare($query) or die $dbhCentreon->errstr; 
    $prep->execute(getCentreonHostID($name), $mapId, $name) or die "Error query : $query\n"; 
    $prep->finish(); 
}

#** @method generateNodesWeatherMap()
#   Generate Nodes weathermap
#*
sub generateNodesWeatherMap {
    my ($host,$x,$y,$name);
    foreach my $host (keys %mapper) {
        $name = $Topology{$host}{name};
        $x = $mapper{$host}{x};
        $y = $mapper{$host}{y};
        insertNodeIntoWeatherMap($name);
        writeMap("NODE $name\n");
        writeMap("\tLABEL $name\n");
        if($Topology{$host}{firstParent} == 1) {
            writeMap("\tICON ".$wBoxPar." ".$hBoxPar." box\n");
            writeMap("\tLABELOUTLINECOLOR none\n");
        }
        if($allDepths{$host}>0){
            writeMap("\tLABELFONT 30\n");
        }
        if($allDepths{$host}>1){
            writeMap("\tLABELANGLE 90\n");
        }
        writeMap("\tPOSITION $x $y\n");
        writeMap("\tINFOURL NODEINFOURLTOCHANGE_".getCentreonHostID($name)."\n");
        writeMap("\n");
    }
}

#** @method countMetrics()
#   Count all metrics in centreon storage database
#   @retval Number of metrics
#*
sub countMetrics {
    my ($query,$nbrMetrics,$prep);
    $query = "SELECT COUNT(metric_id) FROM metrics WHERE metric_name LIKE 'traffic_%'";
    $prep = $dbhCentstorage->prepare($query) or die $dbhCentstorage->errstr;
    $prep->execute() or die "Error query : $query\n";
    ($nbrMetrics) = $prep->fetchrow_array;

    return $nbrMetrics;
}

#** @method getMetricInformation($name,$port)
#   Get Metric RRD information
#
#   @param  $name   name of host
#   @param  $port   interface 
#   @retval representation of metric for weathermap link
#*
sub getMetricInformation {
    my ($name,$port) = @_;
    my ($query,$data,$svc_id,%traffic,$metric,$prep);
    $svc_id = getCentreonServiceID($name,$port);
    $query = "SELECT m.metric_id AS id, m.metric_name AS name FROM metrics AS m INNER JOIN index_data AS i ON i.id=m.index_id WHERE i.service_id=?";
    $prep = $dbhCentstorage->prepare($query) or die $dbhCentstorage->errstr; 
    $prep->execute($svc_id) or die "Error query : $query\n"; 
    while ( $data = $prep->fetchrow_hashref ) { 
        $traffic{$data->{name}} = $data->{id};
    } 
    $prep->finish(); 
    return $pathMetrics."/::".$traffic{traffic_in}."::".$traffic{traffic_out};
}

#** @method getOverlibInformation($name,$port)
#   Get Weathermap Link Overlib information
#
#   @param  $name   name of host
#   @param  $port   interface 
#   @retval link for overlib graph 
#*
sub getOverlibInformation {
    my ($name,$port) = @_;
    my ($query,$svc_id,$host_id,$index_id,$prep);
    $host_id = getCentreonHostID($name);
    $svc_id = getCentreonServiceID($name,$port);
    $query = "SELECT id FROM index_data WHERE service_id=?";
    $prep = $dbhCentstorage->prepare($query) or die $dbhCentstorage->errstr; 
    $prep->execute($svc_id) or die "Error query : $query\n"; 
    ($index_id) = $prep->fetchrow_array;
    $prep->finish(); 

    return "LINKHOVERURLTOCHANGE_generateODSImage.php?host_id=".$host_id."&svc_id=".$svc_id."&index=".$index_id; 
}

#** @method getInformationUrl($name,$port)
#   Get Weathermap Link Information RL
#
#   @param  $name   name of host
#   @param  $port   interface 
#   @retval link for information url 
#*
sub getInformationUrl {
    my ($name,$port) = @_;
    my ($svc_id,$index_id,$prep,$query);
    
    $svc_id = getCentreonServiceID($name,$port);
    $query = "SELECT id FROM index_data WHERE service_id=?";
    $prep = $dbhCentstorage->prepare($query) or die $dbhCentstorage->errstr; 
    $prep->execute($svc_id) or die "Error query : $query\n"; 
    ($index_id) = $prep->fetchrow_array;
    $prep->finish(); 

    return "LINKINFOURLTOCHANGE_".$index_id; 
}

#** @method insertLinkIntoWeatherMap($nameStart,$nameEnd,$port)
#   Insert link into weathermap database configuration
#
#   @param  $nameStart  Name of start link
#   @param  $nameEnd    Name of end link
#   @param  $port       Port interface
#*
sub insertLinkIntoWeatherMap {
    my ($nameStart,$nameEnd,$port) = @_;
    my ($query,$prep);
    $query = "INSERT INTO pwm_host_link_relation (pwm_map_id, host_host_id, service_service_id, node_start_id, node_end_id) VALUES ( ?, ?, ?, ?, ?)";
    $prep = $dbhCentreon->prepare($query) or die $dbhCentreon->errstr; 
    $prep->execute($mapId, getCentreonHostID($nameStart), getCentreonServiceID($nameStart, $port), $nameStart, $nameEnd) or die "Error query : $query\n"; 
    $prep->finish(); 
}

#** @method generateLinksWeatherMap()
#   Generate Links Weathermap configuration
#*
sub generateLinksWeatherMap {
    my ($linkParents,$nbrLinks,$ip,$ipC,$intC,$ipParent,$fName,$sName,$fNameOff,$sNameOff,$offVert,$offHort,$dontDrawLink,@alreadyLinked);
    $linkParents=-1;
    $nbrLinks=getNbrLinksParents;
    $dontDrawLink=0;
    @alreadyLinked;

    foreach my $ipParent ( @ipParents ) {
        foreach $intC (keys %{$Topology{$ipParent}{children}}) {
            $fNameOff=$fName=$Topology{$ipParent}{name};
            $ipC=$Topology{$ipParent}{children}{$intC}{ip};
            $port=$Topology{$ipParent}{children}{$intC}{port};
            $sNameOff=$sName=$Topology{$ipC}{name};
            if($Topology{$ipParent}{firstParent} == 1) {
                $offVert=$dftOffVert;
                if ( $mapper{$ipC}{y} < ($height/2) ){
                    $offVert=-$offVert;
                }
                $fNameOff=$fName.":0:$offVert";
            }
            if($Topology{$ipC}{firstParent} == 1) {
                $offVert=$dftOffVert;
                if ( $mapper{$ip}{y} < ($height/2) ){
                    $offVert=-$offVert;
                }
                $sNameOff=$sName.":0:$offVert";
            }
            if($Topology{$ipC}{firstParent} == 1 && $Topology{$ipParent}{firstParent} == 1 && $linkParents < ($nbrLinks-1) ){
                $offVert=$dftOffVert;
                $fNameOff=$fName.":".$dftOffHort.":".($offVert*$linkParents);
                $sNameOff=$sName.":".($dftOffHort*-1).":".($offVert*$linkParents);
                $sName=$sName."-".($linkParents+1);
            }elsif($Topology{$ipC}{firstParent} == 1 && $Topology{$ipParent}{firstParent} == 1) {
                $dontDrawLink=1;
            }
            if($dontDrawLink == 0) {
                push(@alreadyLinked, $ipParent."-".$ipC);
                insertLinkIntoWeatherMap($fName,$sName,$port);
                writeMap("LINK $fName~$sName \n");
                writeMap("\tNODES $fNameOff $sNameOff\n");
                writeMap("\tINFOURL ".getInformationUrl($fName, $Topology{$ipParent}{children}{$intC}{port})."\n");
                writeMap("\tTARGET ".getMetricInformation($fName, $Topology{$ipParent}{children}{$intC}{port})."\n");
                writeMap("\tOVERLIBGRAPH ".getOverlibInformation($fName, $Topology{$ipParent}{children}{$intC}{port})."\n");
                $nbrTotalLinks++;
            }
            $dontDrawLink=0;
            if($Topology{$ipC}{firstParent} == 1 && $Topology{$ipParent}{firstParent} == 1 && $linkParents < ($nbrLinks-1) ){
                writeMap("\tBWLABELPOS 60 40\n");
                $linkParents++;
            }
        }
    }
    foreach $ip (keys %Topology) {
        foreach $intC (keys %{$Topology{$ip}{children}}) {
            $fNameOff=$fName=$Topology{$ip}{name};
            $ipC=$Topology{$ip}{children}{$intC}{ip};
            $port=$Topology{$ip}{children}{$intC}{port};
            $sNameOff=$sName=$Topology{$ipC}{name};
            if( ! grep(/^$ip-$ipC$/, @alreadyLinked) && ! grep(/^$ipC-$ip$/, @alreadyLinked) ) {
                push(@alreadyLinked, $ip."-".$ipC);
                insertLinkIntoWeatherMap($fName,$sName,$port);
                writeMap("LINK $fName~$sName \n");
                writeMap("\tNODES $fNameOff $sNameOff\n");
                writeMap("\tINFOURL ".getInformationUrl($fNameOff, $Topology{$ip}{children}{$intC}{port})."\n");
                writeMap("\tTARGET ".getMetricInformation($fNameOff, $Topology{$ip}{children}{$intC}{port})."\n");
                writeMap("\tOVERLIBGRAPH ".getOverlibInformation($fNameOff, $Topology{$ip}{children}{$intC}{port})."\n");
            }
        }
    }
}

#** @method connectToCentreonDatabase()
#   Connect to Centreon MySQL Database
#*
sub connectToCentreonDatabase {
    my (@dbCon);
    $dbCon=split(':',$mysql_host);
    $dbhCentreon = DBI->connect( "DBI:mysql:database=$mysql_database_oreon;host=".$dbCon[0].";port=".$dbCon[1], $mysql_user, $mysql_passwd, { 
        RaiseError => 1,
    }) or die "[ERROR] Unable to connect to database $mysql_database_oreon !\n $! \n $@\n$DBI::errstr";
    $dbhCentstorage = DBI->connect( "DBI:mysql:database=$mysql_database_ods;host=".$dbCon[0].";port=".$dbCon[1], $mysql_user, $mysql_passwd, { 
        RaiseError => 1,
    }) or die "[ERROR] Unable to connect to database $mysql_database_ods !\n $! \n $@\n$DBI::errstr";
}

#** @method generateWeathermap()
#   Generate Weathermap file 
#*
sub generateWeatherMap {
    calculateCoordinatesMap;
    createWeathermap;
    generateNodesWeatherMap;
    generateLinksWeatherMap;
    commitMap;
}

#** @method centreonCommand($object,$cmd,$value)
#   Launch centreon command clapi with parameters
#
#   @param  $object  centreon object type
#   @param  $cmd     centreon command
#   @param  $value   centreon value
#   @retval command output
#*
sub centreonCommand {
    my ($object, $cmd, $value) = @_;
    my $return="";
    if($object eq "") {
        $cmd="$pathClapi -u $loginCentreon -p $pwdCentreon -a $cmd -v \"$value\"";
    }else{
        $cmd="$pathClapi -u $loginCentreon -p $pwdCentreon -o $object -a $cmd -v \"$value\"";
    }
    if($dryrun){
        print "[DRYRUN] ".$cmd."\n";
    }else{
        $return = `$cmd 2>&1`;
        if( $? ) {
            die "Error running [$cmd]\nError : $return";
        }
    }
    return $return; 
}

#** @methode generateCentreonHost()
#   Generate Centreon host configuration
#*
sub generateCentreonHost {
    my ($alreadyConfigured, $ipParent, $name, $value, $parents, $i, $ip, $depth);
    $alreadyConfigured = centreonCommand("HOST","SHOW","");
    foreach $ipParent ( @ipParents ) {
        if(!grep(/$ipParent/,$alreadyConfigured)) {
            $name=$Topology{$ipParent}{name};
            $value="$name;$name;$ipParent;$dftTemplate;$dftPoller;$dftHostGroup";
            centreonCommand("HOST","ADD",$value);
        }
    }
    $alreadyConfigured = centreonCommand("HOST","SHOW","");
    for( $i=1; $i<=$maxDepth; $i++ ) {
        while(($ip,$depth) = each(%allDepths)) {
            if(!grep(/$ip/,$alreadyConfigured) && $depth==$i) {
                $name=$Topology{$ip}{name};
                $value="$name;$name;$ip;$dftTemplate;$dftPoller;$dftHostGroup";
                centreonCommand("HOST","ADD",$value);
                $parents=getAllParentsNameCentreon($ip);
                if(!$parents and $parents ne undef ){
                    centreonCommand("HOST","SETPARENT","$name;$parents");
                }
            }
        }
    }
}

#** @method generateCentreonLink()
#   Generate Centreon service configuration
#*
sub generateCentreonLink {
    my ($ip, $int, $alreadyConfigured,$nameIf );
    $alreadyConfigured = centreonCommand("SERVICE","SHOW","");
    foreach $ip (keys %Topology) {
        $name=$Topology{$ip}{name};
        foreach $int (keys %{$Topology{$ip}{children}}) {
            $nameIf=$Topology{$ip}{children}{$int}{port};
            if(!grep(/$name;If-$nameIf/,$alreadyConfigured)) {
                centreonCommand("SERVICE","ADD","$name;If-$nameIf;generic-service");
                centreonCommand("SERVICE","SETPARAM","$name;If-$nameIf;check_command;check_centreon_traffic_index_64");
                centreonCommand("SERVICE","SETPARAM","$name;If-$nameIf;check_command_arguments;!$int!$checkWarningPct!$checkCriticalPct");
                centreonCommand("SERVICE","SETPARAM","$name;If-$nameIf;graphtemplate;Traffic");
                centreonCommand("SERVICECATEGORY","ADDSERVICE","Traffic;$name,If-$nameIf");
            }
        }
    }
}

#** @method regeneratePoller()
#   Regenerate Poller configuration and restart
#*
sub regeneratePoller {
    centreonCommand("", "POLLERGENERATE", "1");
    centreonCommand("", "CFGMOVE", "1");
    centreonCommand("", "POLLERRESTART", "1");

}

#** @methode public generateCentreon()
#   Generate Centreon configuration
#*
sub generateCentreon {
    generateCentreonHost;
    generateCentreonLink; 
    regeneratePoller;
}

#** 
#   MAIN PROGRAM 
#   Get name of a device via snmp
#*
Getopt::Long::Configure ("bundling");
GetOptions(
   'H=s' => \$hosts,
   'C=s' => \$rocommunity,
   'N=s' => \$weathermapName,
   'd' => \$dryrun,
   'c' => \$onlyCentreon,
   'm' => \$onlyWeathermap,
   'v+' => \$verbose,
   'h' => \$help,
);

&usage( 0 ) if ( $help );
&usage( 0 ) if ( ! $hosts );
&usage( 0 ) if ( ! $rocommunity );
&usage( 0 ) if ( ! $weathermapName );
&usage( 0 ) if ( $onlyCentreon && $onlyWeathermap );

$| = 1;
print "Get Nortel Topology from device ";
@ipParents = split(/;/, $hosts);
foreach my $ipParent ( @ipParents ) {
    getAllIps($ipParent);
}
foreach my $ipParent ( @ipParents ) { 
    $name = snmp_get_one($ipParent, $rocommunity, $ipParent, $sysNameOid);
    $Topology{$ipParent} = {"firstParent"=>1,"name"=>$name,"children"=>()};
    fetchDevice($ipParent);
}
store \%Topology, 'saveTopo';
store \%Models, 'saveModels';
getTopologyDepth;
print "\tdone\n";
$| = 1;
print "Generate Centreon Check ";
generateCentreon
connectToCentreonDatabase;
$| = 1;
print "\t\tdone\n";
my $beforeNbrMetrics = countMetrics();
$| = 1;
print "Wait to Centreon perform some check ";
while( countMetrics() < ($beforeNbrMetrics + ($nbrTotalLinks*2)) ) {
   print ". ";
   sleep(10);
}
print "Generate Weathermap ";
generateWeatherMap;
print "\t\t\tdone\n";
