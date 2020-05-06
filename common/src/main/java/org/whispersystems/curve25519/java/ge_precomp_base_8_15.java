package org.whispersystems.curve25519.java;

public class ge_precomp_base_8_15 {

    /* base[i][j] = (j+1)*256^i*B */
    static ge_precomp[][] base;

    static {
//CONVERT #include "base.h"
        base = new ge_precomp[32][8];

        base[8][0] = new ge_precomp(
                new int[]{-3017432, 10058206, 1980837, 3964243, 22160966, 12322533, -6431123, -12618185, 12228557, -7003677},
                new int[]{32944382, 14922211, -22844894, 5188528, 21913450, -8719943, 4001465, 13238564, -6114803, 8653815},
                new int[]{22865569, -4652735, 27603668, -12545395, 14348958, 8234005, 24808405, 5719875, 28483275, 2841751}
        );
        base[8][1] = new ge_precomp(
                new int[]{-16420968, -1113305, -327719, -12107856, 21886282, -15552774, -1887966, -315658, 19932058, -12739203},
                new int[]{-11656086, 10087521, -8864888, -5536143, -19278573, -3055912, 3999228, 13239134, -4777469, -13910208},
                new int[]{1382174, -11694719, 17266790, 9194690, -13324356, 9720081, 20403944, 11284705, -14013818, 3093230}
        );
        base[8][2] = new ge_precomp(
                new int[]{16650921, -11037932, -1064178, 1570629, -8329746, 7352753, -302424, 16271225, -24049421, -6691850},
                new int[]{-21911077, -5927941, -4611316, -5560156, -31744103, -10785293, 24123614, 15193618, -21652117, -16739389},
                new int[]{-9935934, -4289447, -25279823, 4372842, 2087473, 10399484, 31870908, 14690798, 17361620, 11864968}
        );
        base[8][3] = new ge_precomp(
                new int[]{-11307610, 6210372, 13206574, 5806320, -29017692, -13967200, -12331205, -7486601, -25578460, -16240689},
                new int[]{14668462, -12270235, 26039039, 15305210, 25515617, 4542480, 10453892, 6577524, 9145645, -6443880},
                new int[]{5974874, 3053895, -9433049, -10385191, -31865124, 3225009, -7972642, 3936128, -5652273, -3050304}
        );
        base[8][4] = new ge_precomp(
                new int[]{30625386, -4729400, -25555961, -12792866, -20484575, 7695099, 17097188, -16303496, -27999779, 1803632},
                new int[]{-3553091, 9865099, -5228566, 4272701, -5673832, -16689700, 14911344, 12196514, -21405489, 7047412},
                new int[]{20093277, 9920966, -11138194, -5343857, 13161587, 12044805, -32856851, 4124601, -32343828, -10257566}
        );
        base[8][5] = new ge_precomp(
                new int[]{-20788824, 14084654, -13531713, 7842147, 19119038, -13822605, 4752377, -8714640, -21679658, 2288038},
                new int[]{-26819236, -3283715, 29965059, 3039786, -14473765, 2540457, 29457502, 14625692, -24819617, 12570232},
                new int[]{-1063558, -11551823, 16920318, 12494842, 1278292, -5869109, -21159943, -3498680, -11974704, 4724943}
        );
        base[8][6] = new ge_precomp(
                new int[]{17960970, -11775534, -4140968, -9702530, -8876562, -1410617, -12907383, -8659932, -29576300, 1903856},
                new int[]{23134274, -14279132, -10681997, -1611936, 20684485, 15770816, -12989750, 3190296, 26955097, 14109738},
                new int[]{15308788, 5320727, -30113809, -14318877, 22902008, 7767164, 29425325, -11277562, 31960942, 11934971}
        );
        base[8][7] = new ge_precomp(
                new int[]{-27395711, 8435796, 4109644, 12222639, -24627868, 14818669, 20638173, 4875028, 10491392, 1379718},
                new int[]{-13159415, 9197841, 3875503, -8936108, -1383712, -5879801, 33518459, 16176658, 21432314, 12180697},
                new int[]{-11787308, 11500838, 13787581, -13832590, -22430679, 10140205, 1465425, 12689540, -10301319, -13872883}
        );
        base[9][0] = new ge_precomp(
                new int[]{5414091, -15386041, -21007664, 9643570, 12834970, 1186149, -2622916, -1342231, 26128231, 6032912},
                new int[]{-26337395, -13766162, 32496025, -13653919, 17847801, -12669156, 3604025, 8316894, -25875034, -10437358},
                new int[]{3296484, 6223048, 24680646, -12246460, -23052020, 5903205, -8862297, -4639164, 12376617, 3188849}
        );
        base[9][1] = new ge_precomp(
                new int[]{29190488, -14659046, 27549113, -1183516, 3520066, -10697301, 32049515, -7309113, -16109234, -9852307},
                new int[]{-14744486, -9309156, 735818, -598978, -20407687, -5057904, 25246078, -15795669, 18640741, -960977},
                new int[]{-6928835, -16430795, 10361374, 5642961, 4910474, 12345252, -31638386, -494430, 10530747, 1053335}
        );
        base[9][2] = new ge_precomp(
                new int[]{-29265967, -14186805, -13538216, -12117373, -19457059, -10655384, -31462369, -2948985, 24018831, 15026644},
                new int[]{-22592535, -3145277, -2289276, 5953843, -13440189, 9425631, 25310643, 13003497, -2314791, -15145616},
                new int[]{-27419985, -603321, -8043984, -1669117, -26092265, 13987819, -27297622, 187899, -23166419, -2531735}
        );
        base[9][3] = new ge_precomp(
                new int[]{-21744398, -13810475, 1844840, 5021428, -10434399, -15911473, 9716667, 16266922, -5070217, 726099},
                new int[]{29370922, -6053998, 7334071, -15342259, 9385287, 2247707, -13661962, -4839461, 30007388, -15823341},
                new int[]{-936379, 16086691, 23751945, -543318, -1167538, -5189036, 9137109, 730663, 9835848, 4555336}
        );
        base[9][4] = new ge_precomp(
                new int[]{-23376435, 1410446, -22253753, -12899614, 30867635, 15826977, 17693930, 544696, -11985298, 12422646},
                new int[]{31117226, -12215734, -13502838, 6561947, -9876867, -12757670, -5118685, -4096706, 29120153, 13924425},
                new int[]{-17400879, -14233209, 19675799, -2734756, -11006962, -5858820, -9383939, -11317700, 7240931, -237388}
        );
        base[9][5] = new ge_precomp(
                new int[]{-31361739, -11346780, -15007447, -5856218, -22453340, -12152771, 1222336, 4389483, 3293637, -15551743},
                new int[]{-16684801, -14444245, 11038544, 11054958, -13801175, -3338533, -24319580, 7733547, 12796905, -6335822},
                new int[]{-8759414, -10817836, -25418864, 10783769, -30615557, -9746811, -28253339, 3647836, 3222231, -11160462}
        );
        base[9][6] = new ge_precomp(
                new int[]{18606113, 1693100, -25448386, -15170272, 4112353, 10045021, 23603893, -2048234, -7550776, 2484985},
                new int[]{9255317, -3131197, -12156162, -1004256, 13098013, -9214866, 16377220, -2102812, -19802075, -3034702},
                new int[]{-22729289, 7496160, -5742199, 11329249, 19991973, -3347502, -31718148, 9936966, -30097688, -10618797}
        );
        base[9][7] = new ge_precomp(
                new int[]{21878590, -5001297, 4338336, 13643897, -3036865, 13160960, 19708896, 5415497, -7360503, -4109293},
                new int[]{27736861, 10103576, 12500508, 8502413, -3413016, -9633558, 10436918, -1550276, -23659143, -8132100},
                new int[]{19492550, -12104365, -29681976, -852630, -3208171, 12403437, 30066266, 8367329, 13243957, 8709688}
        );
        base[10][0] = new ge_precomp(
                new int[]{12015105, 2801261, 28198131, 10151021, 24818120, -4743133, -11194191, -5645734, 5150968, 7274186},
                new int[]{2831366, -12492146, 1478975, 6122054, 23825128, -12733586, 31097299, 6083058, 31021603, -9793610},
                new int[]{-2529932, -2229646, 445613, 10720828, -13849527, -11505937, -23507731, 16354465, 15067285, -14147707}
        );
        base[10][1] = new ge_precomp(
                new int[]{7840942, 14037873, -33364863, 15934016, -728213, -3642706, 21403988, 1057586, -19379462, -12403220},
                new int[]{915865, -16469274, 15608285, -8789130, -24357026, 6060030, -17371319, 8410997, -7220461, 16527025},
                new int[]{32922597, -556987, 20336074, -16184568, 10903705, -5384487, 16957574, 52992, 23834301, 6588044}
        );
        base[10][2] = new ge_precomp(
                new int[]{32752030, 11232950, 3381995, -8714866, 22652988, -10744103, 17159699, 16689107, -20314580, -1305992},
                new int[]{-4689649, 9166776, -25710296, -10847306, 11576752, 12733943, 7924251, -2752281, 1976123, -7249027},
                new int[]{21251222, 16309901, -2983015, -6783122, 30810597, 12967303, 156041, -3371252, 12331345, -8237197}
        );
        base[10][3] = new ge_precomp(
                new int[]{8651614, -4477032, -16085636, -4996994, 13002507, 2950805, 29054427, -5106970, 10008136, -4667901},
                new int[]{31486080, 15114593, -14261250, 12951354, 14369431, -7387845, 16347321, -13662089, 8684155, -10532952},
                new int[]{19443825, 11385320, 24468943, -9659068, -23919258, 2187569, -26263207, -6086921, 31316348, 14219878}
        );
        base[10][4] = new ge_precomp(
                new int[]{-28594490, 1193785, 32245219, 11392485, 31092169, 15722801, 27146014, 6992409, 29126555, 9207390},
                new int[]{32382935, 1110093, 18477781, 11028262, -27411763, -7548111, -4980517, 10843782, -7957600, -14435730},
                new int[]{2814918, 7836403, 27519878, -7868156, -20894015, -11553689, -21494559, 8550130, 28346258, 1994730}
        );
        base[10][5] = new ge_precomp(
                new int[]{-19578299, 8085545, -14000519, -3948622, 2785838, -16231307, -19516951, 7174894, 22628102, 8115180},
                new int[]{-30405132, 955511, -11133838, -15078069, -32447087, -13278079, -25651578, 3317160, -9943017, 930272},
                new int[]{-15303681, -6833769, 28856490, 1357446, 23421993, 1057177, 24091212, -1388970, -22765376, -10650715}
        );
        base[10][6] = new ge_precomp(
                new int[]{-22751231, -5303997, -12907607, -12768866, -15811511, -7797053, -14839018, -16554220, -1867018, 8398970},
                new int[]{-31969310, 2106403, -4736360, 1362501, 12813763, 16200670, 22981545, -6291273, 18009408, -15772772},
                new int[]{-17220923, -9545221, -27784654, 14166835, 29815394, 7444469, 29551787, -3727419, 19288549, 1325865}
        );
        base[10][7] = new ge_precomp(
                new int[]{15100157, -15835752, -23923978, -1005098, -26450192, 15509408, 12376730, -3479146, 33166107, -8042750},
                new int[]{20909231, 13023121, -9209752, 16251778, -5778415, -8094914, 12412151, 10018715, 2213263, -13878373},
                new int[]{32529814, -11074689, 30361439, -16689753, -9135940, 1513226, 22922121, 6382134, -5766928, 8371348}
        );
        base[11][0] = new ge_precomp(
                new int[]{9923462, 11271500, 12616794, 3544722, -29998368, -1721626, 12891687, -8193132, -26442943, 10486144},
                new int[]{-22597207, -7012665, 8587003, -8257861, 4084309, -12970062, 361726, 2610596, -23921530, -11455195},
                new int[]{5408411, -1136691, -4969122, 10561668, 24145918, 14240566, 31319731, -4235541, 19985175, -3436086}
        );
        base[11][1] = new ge_precomp(
                new int[]{-13994457, 16616821, 14549246, 3341099, 32155958, 13648976, -17577068, 8849297, 65030, 8370684},
                new int[]{-8320926, -12049626, 31204563, 5839400, -20627288, -1057277, -19442942, 6922164, 12743482, -9800518},
                new int[]{-2361371, 12678785, 28815050, 4759974, -23893047, 4884717, 23783145, 11038569, 18800704, 255233}
        );
        base[11][2] = new ge_precomp(
                new int[]{-5269658, -1773886, 13957886, 7990715, 23132995, 728773, 13393847, 9066957, 19258688, -14753793},
                new int[]{-2936654, -10827535, -10432089, 14516793, -3640786, 4372541, -31934921, 2209390, -1524053, 2055794},
                new int[]{580882, 16705327, 5468415, -2683018, -30926419, -14696000, -7203346, -8994389, -30021019, 7394435}
        );
        base[11][3] = new ge_precomp(
                new int[]{23838809, 1822728, -15738443, 15242727, 8318092, -3733104, -21672180, -3492205, -4821741, 14799921},
                new int[]{13345610, 9759151, 3371034, -16137791, 16353039, 8577942, 31129804, 13496856, -9056018, 7402518},
                new int[]{2286874, -4435931, -20042458, -2008336, -13696227, 5038122, 11006906, -15760352, 8205061, 1607563}
        );
        base[11][4] = new ge_precomp(
                new int[]{14414086, -8002132, 3331830, -3208217, 22249151, -5594188, 18364661, -2906958, 30019587, -9029278},
                new int[]{-27688051, 1585953, -10775053, 931069, -29120221, -11002319, -14410829, 12029093, 9944378, 8024},
                new int[]{4368715, -3709630, 29874200, -15022983, -20230386, -11410704, -16114594, -999085, -8142388, 5640030}
        );
        base[11][5] = new ge_precomp(
                new int[]{10299610, 13746483, 11661824, 16234854, 7630238, 5998374, 9809887, -16694564, 15219798, -14327783},
                new int[]{27425505, -5719081, 3055006, 10660664, 23458024, 595578, -15398605, -1173195, -18342183, 9742717},
                new int[]{6744077, 2427284, 26042789, 2720740, -847906, 1118974, 32324614, 7406442, 12420155, 1994844}
        );
        base[11][6] = new ge_precomp(
                new int[]{14012521, -5024720, -18384453, -9578469, -26485342, -3936439, -13033478, -10909803, 24319929, -6446333},
                new int[]{16412690, -4507367, 10772641, 15929391, -17068788, -4658621, 10555945, -10484049, -30102368, -4739048},
                new int[]{22397382, -7767684, -9293161, -12792868, 17166287, -9755136, -27333065, 6199366, 21880021, -12250760}
        );
        base[11][7] = new ge_precomp(
                new int[]{-4283307, 5368523, -31117018, 8163389, -30323063, 3209128, 16557151, 8890729, 8840445, 4957760},
                new int[]{-15447727, 709327, -6919446, -10870178, -29777922, 6522332, -21720181, 12130072, -14796503, 5005757},
                new int[]{-2114751, -14308128, 23019042, 15765735, -25269683, 6002752, 10183197, -13239326, -16395286, -2176112}
        );
        base[12][0] = new ge_precomp(
                new int[]{-19025756, 1632005, 13466291, -7995100, -23640451, 16573537, -32013908, -3057104, 22208662, 2000468},
                new int[]{3065073, -1412761, -25598674, -361432, -17683065, -5703415, -8164212, 11248527, -3691214, -7414184},
                new int[]{10379208, -6045554, 8877319, 1473647, -29291284, -12507580, 16690915, 2553332, -3132688, 16400289}
        );
        base[12][1] = new ge_precomp(
                new int[]{15716668, 1254266, -18472690, 7446274, -8448918, 6344164, -22097271, -7285580, 26894937, 9132066},
                new int[]{24158887, 12938817, 11085297, -8177598, -28063478, -4457083, -30576463, 64452, -6817084, -2692882},
                new int[]{13488534, 7794716, 22236231, 5989356, 25426474, -12578208, 2350710, -3418511, -4688006, 2364226}
        );
        base[12][2] = new ge_precomp(
                new int[]{16335052, 9132434, 25640582, 6678888, 1725628, 8517937, -11807024, -11697457, 15445875, -7798101},
                new int[]{29004207, -7867081, 28661402, -640412, -12794003, -7943086, 31863255, -4135540, -278050, -15759279},
                new int[]{-6122061, -14866665, -28614905, 14569919, -10857999, -3591829, 10343412, -6976290, -29828287, -10815811}
        );
        base[12][3] = new ge_precomp(
                new int[]{27081650, 3463984, 14099042, -4517604, 1616303, -6205604, 29542636, 15372179, 17293797, 960709},
                new int[]{20263915, 11434237, -5765435, 11236810, 13505955, -10857102, -16111345, 6493122, -19384511, 7639714},
                new int[]{-2830798, -14839232, 25403038, -8215196, -8317012, -16173699, 18006287, -16043750, 29994677, -15808121}
        );
        base[12][4] = new ge_precomp(
                new int[]{9769828, 5202651, -24157398, -13631392, -28051003, -11561624, -24613141, -13860782, -31184575, 709464},
                new int[]{12286395, 13076066, -21775189, -1176622, -25003198, 4057652, -32018128, -8890874, 16102007, 13205847},
                new int[]{13733362, 5599946, 10557076, 3195751, -5557991, 8536970, -25540170, 8525972, 10151379, 10394400}
        );
        base[12][5] = new ge_precomp(
                new int[]{4024660, -16137551, 22436262, 12276534, -9099015, -2686099, 19698229, 11743039, -33302334, 8934414},
                new int[]{-15879800, -4525240, -8580747, -2934061, 14634845, -698278, -9449077, 3137094, -11536886, 11721158},
                new int[]{17555939, -5013938, 8268606, 2331751, -22738815, 9761013, 9319229, 8835153, -9205489, -1280045}
        );
        base[12][6] = new ge_precomp(
                new int[]{-461409, -7830014, 20614118, 16688288, -7514766, -4807119, 22300304, 505429, 6108462, -6183415},
                new int[]{-5070281, 12367917, -30663534, 3234473, 32617080, -8422642, 29880583, -13483331, -26898490, -7867459},
                new int[]{-31975283, 5726539, 26934134, 10237677, -3173717, -605053, 24199304, 3795095, 7592688, -14992079}
        );
        base[12][7] = new ge_precomp(
                new int[]{21594432, -14964228, 17466408, -4077222, 32537084, 2739898, 6407723, 12018833, -28256052, 4298412},
                new int[]{-20650503, -11961496, -27236275, 570498, 3767144, -1717540, 13891942, -1569194, 13717174, 10805743},
                new int[]{-14676630, -15644296, 15287174, 11927123, 24177847, -8175568, -796431, 14860609, -26938930, -5863836}
        );
        base[13][0] = new ge_precomp(
                new int[]{12962541, 5311799, -10060768, 11658280, 18855286, -7954201, 13286263, -12808704, -4381056, 9882022},
                new int[]{18512079, 11319350, -20123124, 15090309, 18818594, 5271736, -22727904, 3666879, -23967430, -3299429},
                new int[]{-6789020, -3146043, 16192429, 13241070, 15898607, -14206114, -10084880, -6661110, -2403099, 5276065}
        );
        base[13][1] = new ge_precomp(
                new int[]{30169808, -5317648, 26306206, -11750859, 27814964, 7069267, 7152851, 3684982, 1449224, 13082861},
                new int[]{10342826, 3098505, 2119311, 193222, 25702612, 12233820, 23697382, 15056736, -21016438, -8202000},
                new int[]{-33150110, 3261608, 22745853, 7948688, 19370557, -15177665, -26171976, 6482814, -10300080, -11060101}
        );
        base[13][2] = new ge_precomp(
                new int[]{32869458, -5408545, 25609743, 15678670, -10687769, -15471071, 26112421, 2521008, -22664288, 6904815},
                new int[]{29506923, 4457497, 3377935, -9796444, -30510046, 12935080, 1561737, 3841096, -29003639, -6657642},
                new int[]{10340844, -6630377, -18656632, -2278430, 12621151, -13339055, 30878497, -11824370, -25584551, 5181966}
        );
        base[13][3] = new ge_precomp(
                new int[]{25940115, -12658025, 17324188, -10307374, -8671468, 15029094, 24396252, -16450922, -2322852, -12388574},
                new int[]{-21765684, 9916823, -1300409, 4079498, -1028346, 11909559, 1782390, 12641087, 20603771, -6561742},
                new int[]{-18882287, -11673380, 24849422, 11501709, 13161720, -4768874, 1925523, 11914390, 4662781, 7820689}
        );
        base[13][4] = new ge_precomp(
                new int[]{12241050, -425982, 8132691, 9393934, 32846760, -1599620, 29749456, 12172924, 16136752, 15264020},
                new int[]{-10349955, -14680563, -8211979, 2330220, -17662549, -14545780, 10658213, 6671822, 19012087, 3772772},
                new int[]{3753511, -3421066, 10617074, 2028709, 14841030, -6721664, 28718732, -15762884, 20527771, 12988982}
        );
        base[13][5] = new ge_precomp(
                new int[]{-14822485, -5797269, -3707987, 12689773, -898983, -10914866, -24183046, -10564943, 3299665, -12424953},
                new int[]{-16777703, -15253301, -9642417, 4978983, 3308785, 8755439, 6943197, 6461331, -25583147, 8991218},
                new int[]{-17226263, 1816362, -1673288, -6086439, 31783888, -8175991, -32948145, 7417950, -30242287, 1507265}
        );
        base[13][6] = new ge_precomp(
                new int[]{29692663, 6829891, -10498800, 4334896, 20945975, -11906496, -28887608, 8209391, 14606362, -10647073},
                new int[]{-3481570, 8707081, 32188102, 5672294, 22096700, 1711240, -33020695, 9761487, 4170404, -2085325},
                new int[]{-11587470, 14855945, -4127778, -1531857, -26649089, 15084046, 22186522, 16002000, -14276837, -8400798}
        );
        base[13][7] = new ge_precomp(
                new int[]{-4811456, 13761029, -31703877, -2483919, -3312471, 7869047, -7113572, -9620092, 13240845, 10965870},
                new int[]{-7742563, -8256762, -14768334, -13656260, -23232383, 12387166, 4498947, 14147411, 29514390, 4302863},
                new int[]{-13413405, -12407859, 20757302, -13801832, 14785143, 8976368, -5061276, -2144373, 17846988, -13971927}
        );
        base[14][0] = new ge_precomp(
                new int[]{-2244452, -754728, -4597030, -1066309, -6247172, 1455299, -21647728, -9214789, -5222701, 12650267},
                new int[]{-9906797, -16070310, 21134160, 12198166, -27064575, 708126, 387813, 13770293, -19134326, 10958663},
                new int[]{22470984, 12369526, 23446014, -5441109, -21520802, -9698723, -11772496, -11574455, -25083830, 4271862}
        );
        base[14][1] = new ge_precomp(
                new int[]{-25169565, -10053642, -19909332, 15361595, -5984358, 2159192, 75375, -4278529, -32526221, 8469673},
                new int[]{15854970, 4148314, -8893890, 7259002, 11666551, 13824734, -30531198, 2697372, 24154791, -9460943},
                new int[]{15446137, -15806644, 29759747, 14019369, 30811221, -9610191, -31582008, 12840104, 24913809, 9815020}
        );
        base[14][2] = new ge_precomp(
                new int[]{-4709286, -5614269, -31841498, -12288893, -14443537, 10799414, -9103676, 13438769, 18735128, 9466238},
                new int[]{11933045, 9281483, 5081055, -5183824, -2628162, -4905629, -7727821, -10896103, -22728655, 16199064},
                new int[]{14576810, 379472, -26786533, -8317236, -29426508, -10812974, -102766, 1876699, 30801119, 2164795}
        );
        base[14][3] = new ge_precomp(
                new int[]{15995086, 3199873, 13672555, 13712240, -19378835, -4647646, -13081610, -15496269, -13492807, 1268052},
                new int[]{-10290614, -3659039, -3286592, 10948818, 23037027, 3794475, -3470338, -12600221, -17055369, 3565904},
                new int[]{29210088, -9419337, -5919792, -4952785, 10834811, -13327726, -16512102, -10820713, -27162222, -14030531}
        );
        base[14][4] = new ge_precomp(
                new int[]{-13161890, 15508588, 16663704, -8156150, -28349942, 9019123, -29183421, -3769423, 2244111, -14001979},
                new int[]{-5152875, -3800936, -9306475, -6071583, 16243069, 14684434, -25673088, -16180800, 13491506, 4641841},
                new int[]{10813417, 643330, -19188515, -728916, 30292062, -16600078, 27548447, -7721242, 14476989, -12767431}
        );
        base[14][5] = new ge_precomp(
                new int[]{10292079, 9984945, 6481436, 8279905, -7251514, 7032743, 27282937, -1644259, -27912810, 12651324},
                new int[]{-31185513, -813383, 22271204, 11835308, 10201545, 15351028, 17099662, 3988035, 21721536, -3148940},
                new int[]{10202177, -6545839, -31373232, -9574638, -32150642, -8119683, -12906320, 3852694, 13216206, 14842320}
        );
        base[14][6] = new ge_precomp(
                new int[]{-15815640, -10601066, -6538952, -7258995, -6984659, -6581778, -31500847, 13765824, -27434397, 9900184},
                new int[]{14465505, -13833331, -32133984, -14738873, -27443187, 12990492, 33046193, 15796406, -7051866, -8040114},
                new int[]{30924417, -8279620, 6359016, -12816335, 16508377, 9071735, -25488601, 15413635, 9524356, -7018878}
        );
        base[14][7] = new ge_precomp(
                new int[]{12274201, -13175547, 32627641, -1785326, 6736625, 13267305, 5237659, -5109483, 15663516, 4035784},
                new int[]{-2951309, 8903985, 17349946, 601635, -16432815, -4612556, -13732739, -15889334, -22258478, 4659091},
                new int[]{-16916263, -4952973, -30393711, -15158821, 20774812, 15897498, 5736189, 15026997, -2178256, -13455585}
        );
        base[15][0] = new ge_precomp(
                new int[]{-8858980, -2219056, 28571666, -10155518, -474467, -10105698, -3801496, 278095, 23440562, -290208},
                new int[]{10226241, -5928702, 15139956, 120818, -14867693, 5218603, 32937275, 11551483, -16571960, -7442864},
                new int[]{17932739, -12437276, -24039557, 10749060, 11316803, 7535897, 22503767, 5561594, -3646624, 3898661}
        );
        base[15][1] = new ge_precomp(
                new int[]{7749907, -969567, -16339731, -16464, -25018111, 15122143, -1573531, 7152530, 21831162, 1245233},
                new int[]{26958459, -14658026, 4314586, 8346991, -5677764, 11960072, -32589295, -620035, -30402091, -16716212},
                new int[]{-12165896, 9166947, 33491384, 13673479, 29787085, 13096535, 6280834, 14587357, -22338025, 13987525}
        );
        base[15][2] = new ge_precomp(
                new int[]{-24349909, 7778775, 21116000, 15572597, -4833266, -5357778, -4300898, -5124639, -7469781, -2858068},
                new int[]{9681908, -6737123, -31951644, 13591838, -6883821, 386950, 31622781, 6439245, -14581012, 4091397},
                new int[]{-8426427, 1470727, -28109679, -1596990, 3978627, -5123623, -19622683, 12092163, 29077877, -14741988}
        );
        base[15][3] = new ge_precomp(
                new int[]{5269168, -6859726, -13230211, -8020715, 25932563, 1763552, -5606110, -5505881, -20017847, 2357889},
                new int[]{32264008, -15407652, -5387735, -1160093, -2091322, -3946900, 23104804, -12869908, 5727338, 189038},
                new int[]{14609123, -8954470, -6000566, -16622781, -14577387, -7743898, -26745169, 10942115, -25888931, -14884697}
        );
        base[15][4] = new ge_precomp(
                new int[]{20513500, 5557931, -15604613, 7829531, 26413943, -2019404, -21378968, 7471781, 13913677, -5137875},
                new int[]{-25574376, 11967826, 29233242, 12948236, -6754465, 4713227, -8940970, 14059180, 12878652, 8511905},
                new int[]{-25656801, 3393631, -2955415, -7075526, -2250709, 9366908, -30223418, 6812974, 5568676, -3127656}
        );
        base[15][5] = new ge_precomp(
                new int[]{11630004, 12144454, 2116339, 13606037, 27378885, 15676917, -17408753, -13504373, -14395196, 8070818},
                new int[]{27117696, -10007378, -31282771, -5570088, 1127282, 12772488, -29845906, 10483306, -11552749, -1028714},
                new int[]{10637467, -5688064, 5674781, 1072708, -26343588, -6982302, -1683975, 9177853, -27493162, 15431203}
        );
        base[15][6] = new ge_precomp(
                new int[]{20525145, 10892566, -12742472, 12779443, -29493034, 16150075, -28240519, 14943142, -15056790, -7935931},
                new int[]{-30024462, 5626926, -551567, -9981087, 753598, 11981191, 25244767, -3239766, -3356550, 9594024},
                new int[]{-23752644, 2636870, -5163910, -10103818, 585134, 7877383, 11345683, -6492290, 13352335, -10977084}
        );
        base[15][7] = new ge_precomp(
                new int[]{-1931799, -5407458, 3304649, -12884869, 17015806, -4877091, -29783850, -7752482, -13215537, -319204},
                new int[]{20239939, 6607058, 6203985, 3483793, -18386976, -779229, -20723742, 15077870, -22750759, 14523817},
                new int[]{27406042, -6041657, 27423596, -4497394, 4996214, 10002360, -28842031, -4545494, -30172742, -4805667}
        );
    }
}
