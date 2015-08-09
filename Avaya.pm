#!/usr/bin/perl

package Avaya;

use base 'Exporter';

our @EXPORT_OK = qw(%AvayaModel);

%AvayaModel=(
1 => {'model'=>'other','desc'=>'none of the following'},
2 => {'model'=>'m3000','desc'=>'product 3000'},
3 => {'model'=>'m3030','desc'=>'product 3030'},
4 => {'model'=>'m2310','desc'=>'product 2310'},
5 => {'model'=>'m2810','desc'=>'product 2810'},
6 => {'model'=>'m2912','desc'=>'product 2912'},
7 => {'model'=>'m2914','desc'=>'product 2914'},
8 => {'model'=>'m271x','desc'=>'product 271x'},
9 => {'model'=>'m2813','desc'=>'product 2813'},
10 => {'model'=>'m2814','desc'=>'product 2814'},
11 => {'model'=>'m2915','desc'=>'product 2915'},
12 => {'model'=>'m5000','desc'=>'product 5000'},
13 => {'model'=>'m2813SA','desc'=>'product 2813SA'},
14 => {'model'=>'m2814SA','desc'=>'product 2814SA'},
15 => {'model'=>'m810M','desc'=>'product 810M'},
16 => {'model'=>'m1032x','desc'=>'product EtherCell'},
17 => {'model'=>'m5005','desc'=>'product 5005'},
18 => {'model'=>'mAlcatelEthConc','desc'=>'product Alcatel Ethernet workgroup conc.'},
20 => {'model'=>'m2715SA','desc'=>'product 2715SA'},
21 => {'model'=>'m2486','desc'=>'product 2486'},
22 => {'model'=>'m28xxx','desc'=>'product 28000 series'},
23 => {'model'=>'m2300x','desc'=>'product 23000 series'},
24 => {'model'=>'m5DN00x','desc'=>'product 5DN00x series'},
25 => {'model'=>'mBayStackEth','desc'=>'product BayStack Ethernet'},
26 => {'model'=>'m2310x','desc'=>'product 23100 series'},
27 => {'model'=>'mBayStack100Hub','desc'=>'product 100Base-T Hub'},
28 => {'model'=>'m3000FastEth','desc'=>'product 3000 Fast Ethernet'},
29 => {'model'=>'mXediaSwitch','desc'=>'product Orion switch'},
30 => {'model'=>'notUsed','desc'=>'not used'},
31 => {'model'=>'m28200EthSwitch','desc'=>'product DDS'},
32 => {'model'=>'mCent6Slot','desc'=>'product Centillion'},
33 => {'model'=>'mCent12Slot','desc'=>'product Centillion'},
34 => {'model'=>'mCent1Slot','desc'=>'product Centillion'},
35 => {'model'=>'mBayStack301','desc'=>'product BayStack 301'},
36 => {'model'=>'mBayStackTr','desc'=>'product BayStack TokenRing Hub'},
37 => {'model'=>'mFVC10625','desc'=>'product FVC Multimedia Switch'},
38 => {'model'=>'mSwitchNode','desc'=>'product Switch Node'},
39 => {'model'=>'mBayStack302','desc'=>'product BayStack 302 Switch'},
40 => {'model'=>'mBayStack350','desc'=>'product BayStack 350 Switch'},
41 => {'model'=>'mBayStack150','desc'=>'product BayStack 150 Ethernet Hub'},
42 => {'model'=>'mCent50N3Slot','desc'=>'product Centillion 50N switch'},
43 => {'model'=>'mCent50T3Slot','desc'=>'product Centillion 50T switch'},
44 => {'model'=>'mBayStack303-304','desc'=>'product BayStack 303 and 304 Switches'},
45 => {'model'=>'mBayStack200','desc'=>'product BayStack 200 Ethernet Hub'},
46 => {'model'=>'mBayStack250','desc'=>'product BayStack 250 10/100 Ethernet Hub'},
48 => {'model'=>'mBayStack450','desc'=>'product BayStack 450 10/100/1000 Switches'},
49 => {'model'=>'mBayStack410','desc'=>'product BayStack 410 10/100 Switches'},
50 => {'model'=>'mPassport1200','desc'=>'product Passport 1200 L3 Switch'},
51 => {'model'=>'mPassport1250','desc'=>'product Passport 1250 L3 Switch'},
52 => {'model'=>'mPassport1100','desc'=>'product Passport 1100 L3 Switch'},
53 => {'model'=>'mPassport1150','desc'=>'product Passport 1150 L3 Switch'},
54 => {'model'=>'mPassport1050','desc'=>'product Passport 1050 L3 Switch'},
55 => {'model'=>'mPassport1051','desc'=>'product Passport 1051 L3 Switch'},
56 => {'model'=>'mPassport8610','desc'=>'product Passport 8610 L3 Switch'},
57 => {'model'=>'mPassport8606','desc'=>'product Passport 8606 L3 Switch'},
58 => {'model'=>'mPassport8010','desc'=>'product Passport 8010'},
59 => {'model'=>'mPassport8006','desc'=>'product Passport 8006'},
60 => {'model'=>'mBayStack670','desc'=>'product BayStack 670 wireless access point'},
61 => {'model'=>'mPassport740','desc'=>'product Passport 740'},
62 => {'model'=>'mPassport750','desc'=>'product Passport 750'},
63 => {'model'=>'mPassport790','desc'=>'product Passport 790'},
64 => {'model'=>'mBPS2000','desc'=>'product Business Policy Switch 2000 10/100 Switches'},
65 => {'model'=>'mPassport8110','desc'=>'product Passport 8110 L2 Switch'},
66 => {'model'=>'mPassport8106','desc'=>'product Passport 8106 L2 Switch'},
67 => {'model'=>'mBayStack3580','desc'=>'product BayStack 3580 Gig Switch'},
68 => {'model'=>'mBayStack10','desc'=>'product BayStack 10 Power Supply Unit'},
69 => {'model'=>'mBayStack420','desc'=>'product BayStack 420 10/100 Switch'},
70 => {'model'=>'mMetro1200ESM','desc'=>'product OPTera Metro 1200 Ethernet Service Module'},
71 => {'model'=>'mPassport8010co','desc'=>'product OPTera 8010co'},
72 => {'model'=>'mPassport8610co','desc'=>'product OPTera 8610co L3 switch'},
73 => {'model'=>'mPassport8110co','desc'=>'product OPTera 8110co L2 switch'},
74 => {'model'=>'mPassport8003','desc'=>'product OPTera 8003'},
75 => {'model'=>'mPassport8603','desc'=>'product OPTera 8603 L3 switch'},
76 => {'model'=>'mPassport8103','desc'=>'product OPTera 8103 L2 switch'},
77 => {'model'=>'mBayStack380','desc'=>'product BayStack 380 10/100/1000 Switch'},
78 => {'model'=>'mES470-48T','desc'=>'product Ethernet Switch 470-48T'},
79 => {'model'=>'mMetro1450ESM','desc'=>'product OPTera Metro 1450 Ethernet Service Module'},
80 => {'model'=>'mMetro1400ESM','desc'=>'product OPTera Metro 1400 Ethernet Service Module'},
81 => {'model'=>'mAlteonSwitch','desc'=>'product Alteon Switch Family'},
82 => {'model'=>'mES460-24T-PWR','desc'=>'product Ethernet Switch 460-24T-PWR'},
83 => {'model'=>'mMetro8010','desc'=>'product OPTera Metro 8010 OPM L2 Switch'},
84 => {'model'=>'mMetro8010co','desc'=>'product OPTera Metro 8010co OPM L2 Switch'},
85 => {'model'=>'mMetro8006','desc'=>'product OPTera Metro 8006 OPM L2 Switch'},
86 => {'model'=>'mMetro8003','desc'=>'product OPTera Metro 8003 OPM L2 Switch'},
87 => {'model'=>'mAlteon180e','desc'=>'product Alteon 180e'},
88 => {'model'=>'mAlteonAD3','desc'=>'product Alteon AD3'},
89 => {'model'=>'mAlteon184','desc'=>'product Alteon 184'},
90 => {'model'=>'mAlteonAD4','desc'=>'product Alteon AD4'},
91 => {'model'=>'mPassport1424','desc'=>'product Passport 1424 L3 switch'},
92 => {'model'=>'mPassport1648','desc'=>'product Passport 1648 L3 switch'},
93 => {'model'=>'mPassport1612','desc'=>'product Passport 1612 L3 switch'},
94 => {'model'=>'mPassport1624','desc'=>'product Passport 1624 L3 switch'},
95 => {'model'=>'mBayStack380-24F','desc'=>'product BayStack 380-24F Fiber 1000 Switch'},
96 => {'model'=>'mERS5510-24T','desc'=>'product Ethernet Routing Switch 5510-24T'},
97 => {'model'=>'mERS5510-48T','desc'=>'product Ethernet Routing Switch 5510-48T'},
98 => {'model'=>'mES470-24T','desc'=>'product Ethernet Switch 470-24T'},
99 => {'model'=>'mWLANAccessPoint2220','desc'=>'product Nortel Networks Wireless LAN Access Point 2220'},
100 => {'model'=>'mPassport2402','desc'=>'product Passport RBS 2402 L3 switch'},
101 => {'model'=>'mAlteon2424','desc'=>'product Alteon Application Switch 2424'},
102 => {'model'=>'mAlteon2224','desc'=>'product Alteon Application Switch 2224'},
103 => {'model'=>'mAlteon2208','desc'=>'product Alteon Application Switch 2208'},
104 => {'model'=>'mAlteon2216','desc'=>'product Alteon Application Switch 2216'},
105 => {'model'=>'mAlteon3408','desc'=>'product Alteon Application Switch 3408'},
106 => {'model'=>'mAlteon3416','desc'=>'product Alteon Application Switch 3416'},
107 => {'model'=>'mWLANSecuritySwitch2250','desc'=>'product Nortel Networks Wireless LAN SecuritySwitch 2250'},
108 => {'model'=>'mES425-48T','desc'=>'product Ethernet Switch 425-48T'},
109 => {'model'=>'mES425-24T','desc'=>'product Ethernet Switch 425-24T'},
110 => {'model'=>'mWLANAccessPoint2221','desc'=>'product Nortel Networks Wireless LAN Access Point 2221'},
111 => {'model'=>'mMetroESU1800-24T','desc'=>'product Nortel Metro Ethernet Service Unit 24-T SPF switch'},
112 => {'model'=>'mMetroESU1800-24T-LX-DC','desc'=>'product Nortel Metro Ethernet Service Unit 24-T LX DC switch'},
113 => {'model'=>'mPassport8310','desc'=>'product Passport 8300 10-slot chassis'},
114 => {'model'=>'mPassport8306','desc'=>'product Passport 8300 6-slot chassis'},
115 => {'model'=>'mERS5520-24T-PWR','desc'=>'product Ethernet Routing Switch 5520-24T-PWR'},
116 => {'model'=>'mERS5520-48T-PWR','desc'=>'product Ethernet Routing Switch 5520-48T-PWR'},
117 => {'model'=>'mNnVPNGw3050','desc'=>'product Nortel Networks VPN Gateway 3050'},
118 => {'model'=>'mAlteonSSL310','desc'=>'product Alteon SSL 310 10/100'},
119 => {'model'=>'mAlteonSSL310Fiber','desc'=>'product Alteon SSL 310 10/100 Fiber'},
120 => {'model'=>'mAlteonSSL310FIPS','desc'=>'product Alteon SSL 310 10/100 FIPS'},
121 => {'model'=>'mAlteonSSL410','desc'=>'product Alteon SSL 410 10/100/1000'},
122 => {'model'=>'mAlteonSSL410Fiber','desc'=>'product Alteon SSL 410 10/100/1000 Fiber'},
123 => {'model'=>'mAlteonAS2424SSL','desc'=>'product Alteon Application Switch 2424-SSL'},
124 => {'model'=>'mES325-24T','desc'=>'product Ethernet Switch 325-24T'},
125 => {'model'=>'mES325-24G','desc'=>'product Ethernet Switch 325-24G'},
126 => {'model'=>'mWLANAccessPoint2225','desc'=>'product Nortel Networks Wireless LAN Access Point 2225'},
127 => {'model'=>'mWLANSecuritySwitch2270','desc'=>'product Nortel Networks Wireless LAN SecuritySwitch 2270'},
128 => {'model'=>'mES470-24T-PWR','desc'=>'product 24-port Ethernet Switch 470-24T-PWR'},
129 => {'model'=>'mES470-48T-PWR','desc'=>'product 48-port Ethernet Switch 470-48T-PWR'},
130 => {'model'=>'mERS5530-24TFD','desc'=>'product Ethernet Routing Switch 5530-24TFD'},
131 => {'model'=>'mES3510-24T','desc'=>'product Ethernet Switch 3510-24T'},
132 => {'model'=>'mMetroESU1850-12G-AC','desc'=>'product Nortel Metro Ethernet Service Unit 12G AC L3 switch'},
133 => {'model'=>'mMetroESU1850-12G-DC','desc'=>'product Nortel Metro Ethernet Service Unit 12G DC L3 switch'},
134 => {'model'=>'mSnas4050','desc'=>'Nortel Secure Access Switch'},
135 => {'model'=>'mNnVPNGw3070','desc'=>'Nortel Networks VPN Gateway 3070'},
136 => {'model'=>'mMetro3500','desc'=>'OPTera Metro 3500'},
137 => {'model'=>'mBES1010-24T','desc'=>'SMB BES 1010 24T'},
138 => {'model'=>'mBES1010-48T','desc'=>'SMB BES 1010 48T'},
139 => {'model'=>'mBES1020-24T-PWR','desc'=>'SMB BES 1020 24T PWR'},
140 => {'model'=>'mBES1020-48T-PWR','desc'=>'SMB BES 1020 48T PWR'},
141 => {'model'=>'mBES2010-24T','desc'=>'SMB BES 2010 24T'},
142 => {'model'=>'mBES2010-48T','desc'=>'SMB BES 2010 48T'},
143 => {'model'=>'mBES2020-24T-PWR','desc'=>'SMB BES 2020 24T PWR'},
144 => {'model'=>'mBES2020-48T-PWR','desc'=>'SMB BES 2020 48T PWR'},
145 => {'model'=>'mBES110-24T','desc'=>'SMB BES 110 24T'},
146 => {'model'=>'mBES110-48T','desc'=>'SMB BES 110 48T'},
147 => {'model'=>'mBES120-24T-PWR','desc'=>'SMB BES 120 24T PWR'},
148 => {'model'=>'mBES120-48T-PWR','desc'=>'SMB BES 120 48T PWR'},
149 => {'model'=>'mBES210-24T','desc'=>'SMB BES 210 24T'},
150 => {'model'=>'mBES210-48T','desc'=>'SMB BES 210 48T'},
151 => {'model'=>'mBES220-24T-PWR','desc'=>'SMB BES 220 24T PWR'},
152 => {'model'=>'mBES220-48T-PWR','desc'=>'SMB BES 220 48T PWR'},
153 => {'model'=>'mOME6500','desc'=>'OME 6500'},
154 => {'model'=>'mERS4548GT','desc'=>'Ethernet Routing Switch 4548GT'},
155 => {'model'=>'mERS4548GT-PWR','desc'=>'Ethernet Routing Switch 4548GT-PWR'},
156 => {'model'=>'mERS4550T','desc'=>'Ethernet Routing Switch 4550T'},
157 => {'model'=>'mERS4550T-PWR','desc'=>'Ethernet Routing Switch 4550T-PWR'},
158 => {'model'=>'mERS4526FX','desc'=>'Ethernet Routing Switch 4526FX'},
159 => {'model'=>'mERS2500-26T','desc'=>'Ethernet Routing Switch 2500-26T'},
160 => {'model'=>'mERS2500-26T-PWR','desc'=>'Ethernet Routing Switch 2500-26T-PWR'},
161 => {'model'=>'mERS2500-50T','desc'=>'Ethernet Routing Switch 2500-50T'},
162 => {'model'=>'mERS2500-50T-PWR','desc'=>'Ethernet Routing Switch 2500-50T-PWR'},
167 => {'model'=>'mERS4526GWX-PWR','desc'=>'Ethernet Routing Switch 4526GWX-PWR'},
166 => {'model'=>'mERS4526GWX','desc'=>'Ethernet Routing Switch 4526GWX'},
165 => {'model'=>'mERS4524GT','desc'=>'Ethernet Routing Switch 4524GT'},
164 => {'model'=>'mERS4526T-PWR','desc'=>'Ethernet Routing Switch 4526T-PWR'},
163 => {'model'=>'mERS4526T','desc'=>'Ethernet Routing Switch 4526T'},
192 => {'model'=>'mERS8806','desc'=>'Ethernet Routing Switch 8806'},
);

1;
