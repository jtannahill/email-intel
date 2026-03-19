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


@pytest.fixture
def gmail_headers():
    return SAMPLE_HEADERS_GMAIL


@pytest.fixture
def outlook_headers():
    return SAMPLE_HEADERS_OUTLOOK


@pytest.fixture
def minimal_headers():
    return SAMPLE_HEADERS_MINIMAL
