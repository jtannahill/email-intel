from email_intel.org_decoders import decode_titus, decode_msip, decode_proofpoint, decode_antispam


def test_decode_titus():
    raw = "eyJDYXRlZ29yeUxhYmVscyI6IiIsIk1ldGFkYXRhIjp7Im5zIjoiaHR0cDpcL1wvd3d3LnRpdHVzLmNvbVwvbnNcL0dvbGRtYW5TYWNocyIsImlkIjoiMmJiNzhhMWItOTMyNS00MTg5LWFkMGEtMGE3MDgyMmMxMTE4IiwicHJvcHMiOlt7Im4iOiJBdWQiLCJ2YWxzIjpbeyJ2YWx1ZSI6IlVOUiJ9XX0seyJuIjoiU0UiLCJ2YWxzIjpbeyJ2YWx1ZSI6Ik4ifV19LHsibiI6IkNSIiwidmFscyI6W119XX0sIlN1YmplY3RMYWJlbHMiOltdLCJUTUNWZXJzaW9uIjoiMjMuNi4yNDAzLjEiLCJUcnVzdGVkTGFiZWxIYXNoIjoiTEdHS1hvUW9OcGk2WHFWNkY2ZytaQ1B2YjBidzdkb1YyNUNvUUZ5QmdGTmplWWYzV3BUaFNEd2wydjY2RFhnWCJ9"
    result = decode_titus(raw)
    assert result["namespace"] == "http://www.titus.com/ns/GoldmanSachs"
    assert result["Aud"] == "UNR"
    assert result["SE"] == "N"
    assert result["tmc_version"] == "23.6.2403.1"

def test_decode_titus_invalid():
    assert decode_titus("not-base64!!!") == {}

def test_decode_msip():
    raw = "MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Enabled=true;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Name=Internal GS;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_SetDate=2026-03-19T15:51:22Z;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Method=Standard;"
    result = decode_msip(raw)
    assert result["label_name"] == "Internal GS"
    assert result["enabled"] is True
    assert result["method"] == "Standard"
    assert result["label_id"] == "a64882d5-5c68-43ae-b974-91da18426e9b"

def test_decode_msip_empty():
    assert decode_msip("") == {}

def test_decode_proofpoint():
    raw = "vendor=baseguard engine=ICAP:2.0.293,Aquarius:18.0.1143,Hydra:6.1.51,FMLib:17.12.100.49 definitions=2026-03-19_02,2026-03-19_05,2025-10-01_01"
    result = decode_proofpoint(raw)
    assert result["ICAP"] == "2.0.293"
    assert result["Aquarius"] == "18.0.1143"
    assert result["Hydra"] == "6.1.51"
    assert result["FMLib"] == "17.12.100.49"

def test_decode_proofpoint_empty():
    assert decode_proofpoint("") == {}

def test_decode_antispam():
    antispam = "BCL:0;ARA:13230040|1800799024|376014;"
    forefront = "CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR19MB8278.namprd19.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014);DIR:OUT;SFP:1101;"
    result = decode_antispam(antispam, forefront)
    assert result["BCL"] == 0
    assert result["SCL"] == 1

def test_decode_antispam_missing():
    assert decode_antispam("", "") == {}
