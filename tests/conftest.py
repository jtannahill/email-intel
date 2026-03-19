# tests/conftest.py
import pytest

SAMPLE_HEADERS_GMAIL = """\
Delivered-To: me@gmail.com
Received: by 2002:a05:6902:1024:0:0:0:0 with SMTP id x4csp123456rwn;
        Wed, 19 Mar 2026 11:30:00 -0700 (PDT)
Received: from mail-yw1-f182.google.com (mail-yw1-f182.google.com. [209.85.128.182])
        by mx.google.com with ESMTPS id a1234b5678
        for <me@gmail.com>;
        Wed, 19 Mar 2026 11:29:59 -0700 (PDT)
Received: from [10.0.0.1] (c-74-125-82-42.hsd1.ny.comcast.net. [74.125.82.42])
        by smtp.gmail.com with ESMTPSA id d9876e5432
        for <me@gmail.com>;
        Wed, 19 Mar 2026 11:29:58 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@example.com) smtp.mailfrom=sender@example.com;
       dkim=pass header.d=example.com;
       dmarc=pass (p=REJECT)
From: Sender Name <sender@example.com>
To: me@gmail.com
Subject: Test Email for Analysis
Date: Wed, 19 Mar 2026 14:29:58 -0500
Message-ID: <abc123@mail.gmail.com>
X-Mailer: Apple Mail (2.3654.60.5)
Reply-To: sender@example.com
Content-Type: text/plain; charset="UTF-8"
"""

SAMPLE_HEADERS_OUTLOOK = """\
Received: from BN6PR01MB2345.prod.exchangelabs.com (2603:10b6:404:6a::15)
 by BN6PR01MB6789.prod.exchangelabs.com with HTTPS; Wed, 19 Mar 2026 19:30:00 +0000
Received: from BN3NAM04FT005.eop-nam04.prod.protection.outlook.com
 (2603:10b6:404:6a:cafe::2) by BN6PR01MB2345.prod.exchangelabs.com
 (2603:10b6:404:6a::15) with Microsoft SMTP Server; Wed, 19 Mar 2026 19:29:59 +0000
X-Originating-IP: [203.0.113.45]
Authentication-Results: spf=softfail; dkim=none; dmarc=fail
From: "Marketing Team" <marketing@sketchy.biz>
To: me@outlook.com
Subject: You Won a Prize!
Date: Wed, 19 Mar 2026 15:29:58 -0400
Message-ID: <xyz789@outlook.com>
Reply-To: claim-prize@different-domain.com
List-Unsubscribe: <mailto:unsub@sketchy.biz>
X-Campaign-ID: camp_12345
"""

SAMPLE_HEADERS_MINIMAL = """\
From: bare@example.com
To: me@example.com
Subject: Minimal headers
Date: Wed, 19 Mar 2026 10:00:00 +0000
"""


SAMPLE_HEADERS_GOLDMAN = """\
From: "Yetter, Julia" <Julia.Yetter@gs.com>
To: jtannahill@plocamium.com
Subject: Goldman Sachs Apex Family Office Symposium
Date: Thu, 19 Mar 2026 16:02:01 +0000
Message-Id: <LV3PR19MB82782B39A81C83E557C15BA6844FALV3PR19MB8278.namprd19.prod.outlook.com>
Authentication-Results: mx.google.com; dkim=pass header.i=@gs.com header.s=201802 header.b=Fldn79x9; spf=pass (google.com: domain of julia.yetter@gs.com designates 138.8.105.144 as permitted sender) smtp.mailfrom=Julia.Yetter@gs.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gs.com
X-MS-Exchange-CrossTenant-Id: 38651f6f-836b-4bdf-9615-4e255c290fea
X-MS-Exchange-CrossTenant-AuthSource: LV3PR19MB8278.namprd19.prod.outlook.com
X-Proofpoint-Virus-Version: vendor=baseguard engine=ICAP:2.0.293,Aquarius:18.0.1143,Hydra:6.1.51,FMLib:17.12.100.49 definitions=2026-03-19_02,2026-03-19_05,2025-10-01_01
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014;
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR19MB8278.namprd19.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014);DIR:OUT;SFP:1101;
Msip_Labels: MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Enabled=true;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Name=Internal GS;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_SetDate=2026-03-19T15:51:22Z;MSIP_Label_a64882d5-5c68-43ae-b974-91da18426e9b_Method=Standard;
X-Titus-Metadata-40: eyJDYXRlZ29yeUxhYmVscyI6IiIsIk1ldGFkYXRhIjp7Im5zIjoiaHR0cDpcL1wvd3d3LnRpdHVzLmNvbVwvbnNcL0dvbGRtYW5TYWNocyIsImlkIjoiMmJiNzhhMWItOTMyNS00MTg5LWFkMGEtMGE3MDgyMmMxMTE4IiwicHJvcHMiOlt7Im4iOiJBdWQiLCJ2YWxzIjpbeyJ2YWx1ZSI6IlVOUiJ9XX0seyJuIjoiU0UiLCJ2YWxzIjpbeyJ2YWx1ZSI6Ik4ifV19LHsibiI6IkNSIiwidmFscyI6W119XX0sIlN1YmplY3RMYWJlbHMiOltdLCJUTUNWZXJzaW9uIjoiMjMuNi4yNDAzLjEiLCJUcnVzdGVkTGFiZWxIYXNoIjoiTEdHS1hvUW9OcGk2WHFWNkY2ZytaQ1B2YjBidzdkb1YyNUNvUUZ5QmdGTmplWWYzV3BUaFNEd2wydjY2RFhnWCJ9
Received: from mxe14.gs.com (mxe14.gs.com. [138.8.105.144]) by mx.google.com with ESMTPS id d2e1a72fcca58 for <jtannahill@plocamium.com> (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128); Thu, 19 Mar 2026 09:02:09 -0700 (PDT)
Received: from exhy64417-068.firmwide.corp.gs.com (exhy64417-068.dc.gs.com [10.155.139.215]) by ppa-n-003-d178811.dc.gs.com (PPS) with ESMTPS id 4cw1abn9yr-1 (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT) for <jtannahill@plocamium.com>; Thu, 19 Mar 2026 12:02:05 -0400
Received: from LV3PR19MB8278.namprd19.prod.outlook.com (2603:10b6:408:1a5::17) by PH0PR19MB5646.namprd19.prod.outlook.com (2603:10b6:510:144::20) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9723.19; Thu, 19 Mar 2026 16:02:01 +0000
"""


@pytest.fixture
def goldman_headers():
    return SAMPLE_HEADERS_GOLDMAN


@pytest.fixture
def gmail_headers():
    return SAMPLE_HEADERS_GMAIL


@pytest.fixture
def outlook_headers():
    return SAMPLE_HEADERS_OUTLOOK


@pytest.fixture
def minimal_headers():
    return SAMPLE_HEADERS_MINIMAL
