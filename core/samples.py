"""
Pre-Configured Real-World Test Cases for SIH Evaluation.
Provides instant demonstration emails for AICTE impersonation, BEC fraud, and legitimate mail.
"""

SAMPLE_EMAILS = {
    "aicte_impersonation": {
        "id": "aicte_impersonation",
        "title": "Case 1: AICTE Official Impersonation (Homoglyph + Tor)",
        "description": "High-severity extortion attack spoofing AICTE Approval Bureau via Cyrillic homoglyph domain and Tor exit node.",
        "raw_eml": """Delivered-To: principal@engg-college.ac.in
Received: by 103.141.51.10 with SMTP id inb_srv45;
        Thu, 24 Sep 2026 08:35:12 +0530 (IST)
Received: from mx2.securemail-in.net (mx2.securemail-in.net [194.26.29.112])
        by college-mail.ac.in (MTA Relay) with ESMTP id 88B4C90A;
        Thu, 24 Sep 2026 03:04:45 +0000
Received: from tor-relay.exit-node.de (tor-relay.exit-node.de [185.220.101.5])
        by mx2.securemail-in.net with ESMTP id 11C82F10;
        Thu, 24 Sep 2026 03:02:10 +0000
Authentication-Results: college-mail.ac.in;
        spf=fail (sender IP 185.220.101.5 is not authorized by aicte-india.org);
        dkim=fail (bad signature)
Received-SPF: fail (college-mail.ac.in: domain of aicte-india.org does not designate 185.220.101.5 as permitted sender)
From: "Member Secretary, AICTE" <membersecretary@\u0430icte-india.org>
To: "Principal / Director" <principal@engg-college.ac.in>
Reply-To: "AICTE Desk" <compliance-desk@secure-aicte-portal.top>
Subject: CRITICAL: Immediate Revocation of AICTE Approval for 2026-27 (Action Required within 24 Hours)
Date: Thu, 24 Sep 2026 08:31:00 +0530
Message-ID: <20260924.88123.aicte@secure-portal.top>
Content-Type: text/plain; charset="UTF-8"

URGENT AND CONFIDENTIAL NOTICE:

It has come to the attention of the All India Council for Technical Education (AICTE) Inspection Committee that your institution has failed mandatory compliance parameters under the National Technical Quality Standards 2026.

Unless the compliance regularization penalty of INR 2,50,000 is transferred immediately to the dedicated scrutiny escrow account within 24 hours, your institution's approved seat intake will be suspended and approval revoked with immediate effect.

Please complete the statutory wire transfer immediately:
Account Name: AICTE Regulatory Escrow Bureau
Bank: National Scrutiny Bank
Account Number: 918273645102
IFSC Code: NSCR0001824

Failure to remit the payment within 24 hours will result in immediate police FIR and blacklisting. Access the verification portal here:
http://185.220.101.5/login-verify/portal-auth
"""
    },
    "bec_payment_diversion": {
        "id": "bec_payment_diversion",
        "title": "Case 2: University Vendor Payment Diversion (BEC)",
        "description": "Sophisticated Business Email Compromise requesting urgent diversion of ₹14.5 Lakhs vendor equipment funds.",
        "raw_eml": """Delivered-To: finance-officer@state-univ.edu.in
Received: by 103.141.51.10 with SMTP id mail_hub_01;
        Wed, 23 Sep 2026 14:15:22 +0530 (IST)
Received: from mail-relay.linode-cloud.net ([45.33.32.156])
        by mail-gateway.state-univ.edu.in with ESMTP id 9A72B401;
        Wed, 23 Sep 2026 08:44:10 +0000
Received: from client-workstation.vpn ([198.98.56.12])
        by mail-relay.linode-cloud.net with ESMTP id 5582AA;
        Wed, 23 Sep 2026 08:42:30 +0000
Authentication-Results: state-univ.edu.in;
        spf=softfail;
        dkim=none
From: "National Lab Instruments Vendor" <billing@univ-finance-desk.net>
To: "Finance Officer" <finance-officer@state-univ.edu.in>
Reply-To: "Accounts Department" <settlements@vendor-pay-hub.xyz>
Subject: URGENT: Updated Bank Details for Invoice #INV-2026-8812 (Payment Diversion Notice)
Date: Wed, 23 Sep 2026 14:12:00 +0530
Message-ID: <vendor.invoices.20260923@univ-finance-desk.net>
Content-Type: text/plain; charset="UTF-8"

Dear Finance Officer,

Regarding the outstanding invoice #INV-2026-8812 for the amount of INR 14,50,000 for advanced engineering robotics equipment:

Please be advised that our primary bank account with State Bank of India is undergoing annual statutory audit. Consequently, do not disburse funds to our old account.

Kindly initiate the wire transfer immediately to our updated reserve settlement account:
Account Holder: HighTech Instrument Supplies Pvt Ltd
Account Number: 501004829104
IFSC Code: HDFC0000128
Branch: Cyber City Corporate Branch

Please treat this as urgent to avoid stoppage of equipment deliveries scheduled for tomorrow.
"""
    },
    "scholarship_theft": {
        "id": "scholarship_theft",
        "title": "Case 3: PMSSS Scholarship Phishing (Tor Exit Amsterdam)",
        "description": "Targeted credential harvesting campaign spoofing PM Special Scholarship Scheme via Netherlands Tor relay.",
        "raw_eml": """Delivered-To: student-affairs@engineering-college.edu.in
Received: by 103.141.51.10 with SMTP id hub_delhi_04;
        Fri, 25 Sep 2026 11:20:14 +0530 (IST)
Received: from mx-cloud.protect-gw.in (mx-cloud.protect-gw.in [103.15.24.89])
        by mail.engineering-college.edu.in with ESMTP id 55A9B801;
        Fri, 25 Sep 2026 05:49:10 +0000
Received: from exit-ams-01.privacyfoundation.org ([185.220.102.8])
        by mx-cloud.protect-gw.in with ESMTP id 9928AF10;
        Fri, 25 Sep 2026 05:47:00 +0000
Authentication-Results: engineering-college.edu.in;
        spf=fail (domain pmsss-scholarship-gov.top does not permit 185.220.102.8);
        dkim=fail (signature missing);
        dmarc=fail (p=reject)
From: "PMSSS Central Scholarship Cell" <disbursement@pmsss-scholarship-gov.top>
To: "Scholarship Nodal Officer" <student-affairs@engineering-college.edu.in>
Reply-To: "Verification Desk" <kyc-portal@aicte-grant-apply.xyz>
Subject: URGENT: Discontinuation of PMSSS Student Scholarship Grant (Action Required within 48 Hours)
Date: Fri, 25 Sep 2026 11:15:00 +0530
Message-ID: <pmsss.grant.20260925@pmsss-scholarship-gov.top>
Content-Type: text/plain; charset="UTF-8"

CONFIDENTIAL SCHOLARSHIP ALERT:

According to the latest PMSSS Audit Bureau review, mandatory student Aadhaar and bank account credentials for 24 scholarship beneficiaries enrolled in your institution have been found unverified.

If the credentials are not verified within 48 hours, all disbursed stipend funds of INR 1,20,000 per student will be cancelled and recovery initiated.

Instruct all students to update their biometric Aadhaar credentials immediately:
http://185.220.102.8/portal-verify/student-kyc-auth

Failure to comply within the 48-hour deadline will lead to administrative penalties.
"""
    },
    "incometax_refund": {
        "id": "incometax_refund",
        "title": "Case 4: Income Tax Refund Notice (Bulletproof Relay Bucharest)",
        "description": "Financial phishing notice pretending to be Income Tax e-Filing Bureau harvesting NetBanking logins.",
        "raw_eml": """Delivered-To: faculty-payroll@college.ac.in
Received: by 103.141.51.10 with SMTP id inb_hub_nic;
        Thu, 24 Sep 2026 16:40:10 +0530 (IST)
Received: from relay-gw.secure-host.in (relay-gw.secure-host.in [103.20.12.55])
        by mail.college.ac.in with ESMTP id 7712CC;
        Thu, 24 Sep 2026 11:08:40 +0000
Received: from vps-mail.m247-hosting.ro ([185.193.88.21])
        by relay-gw.secure-host.in with ESMTP id 3321FF;
        Thu, 24 Sep 2026 11:06:12 +0000
Authentication-Results: college.ac.in;
        spf=softfail;
        dkim=none;
        dmarc=fail (p=quarantine)
From: "Income Tax Department e-Filing" <refunds@incometax-efiling-gov.site>
To: "Assessee / Faculty" <faculty-payroll@college.ac.in>
Reply-To: "Tax Settlement Officer" <disbursement@tax-refund-portal.top>
Subject: FINAL NOTICE: Income Tax Refund of INR 42,850 Approved for AY 2026-27 (Claim Immediately)
Date: Thu, 24 Sep 2026 16:35:00 +0530
Message-ID: <itax.efiling.refund.2026@incometax-efiling-gov.site>
Content-Type: text/plain; charset="UTF-8"

Government of India - Income Tax Department (e-Filing Division)

Dear Taxpayer,

We are pleased to inform you that your refund calculation for Assessment Year 2026-27 has been successfully approved for the sum of INR 42,850.

However, your registered State Bank of India account details were declined during electronic clearing due to missing branch IFSC verification.

Please claim and disburse your pending tax refund directly to your net banking account:
http://185.193.88.21/claim-refund/incometax-portal-login

This refund link will expire within 24 hours. Unclaimed refunds will be forfeited to the Treasury.
"""
    },
    "ransomware_invoice": {
        "id": "ransomware_invoice",
        "title": "Case 5: Overdue Lab Hardware Invoice (Hong Kong Dropper Relay)",
        "description": "Spear phishing email delivering an invoice dropper with extortion threats against institutional lab procurement.",
        "raw_eml": """Delivered-To: it-director@polytechnic.edu.in
Received: by 103.141.51.10 with SMTP id poly_gate_02;
        Wed, 23 Sep 2026 17:05:30 +0530 (IST)
Received: from proxy-node.asia-cloud.in ([103.55.10.88])
        by mail.polytechnic.edu.in with ESMTP id 88BC00;
        Wed, 23 Sep 2026 11:34:10 +0000
Received: from mail-node88.ucloud-hk.net ([118.193.41.102])
        by proxy-node.asia-cloud.in with ESMTP id 4410EA;
        Wed, 23 Sep 2026 11:32:00 +0000
Authentication-Results: polytechnic.edu.in;
        spf=neutral;
        dkim=fail
From: "Institutional Hardware Recovery Bureau" <overdue-notices@procurement-orders-desk.cc>
To: "IT Director & Lab Superintendent" <it-director@polytechnic.edu.in>
Reply-To: "Legal Recovery Team" <settlement@vendor-audit-hub.com>
Subject: LEGAL NOTICE: Immediate Settlement for Overdue Lab Server Hardware PO #PO-98104
Date: Wed, 23 Sep 2026 17:00:00 +0530
Message-ID: <legal.notice.hardware.98104@procurement-orders-desk.cc>
Content-Type: text/plain; charset="UTF-8"

ATTENTION: IT DIRECTOR / PROCUREMENT DESK

This serves as a final pre-litigation notice regarding unpaid server rack equipment delivered under Purchase Order #PO-98104 in the amount of INR 8,75,000.

Unless immediate payment verification is completed through the attached encrypted audit invoice, our legal cell will initiate freezing of institutional vendor accounts.

Download and execute the secure verification statement immediately:
http://118.193.41.102/invoices/Invoice-PO98104-AuditStatement.pdf.exe

Treat this as critical. Immediate court litigation will follow within 24 hours.
"""
    },
    "legitimate_circular": {
        "id": "legitimate_circular",
        "title": "Case 6: Legitimate AICTE Official Circular (Clean)",
        "description": "Standard official communication from National Informatics Centre (NIC) with valid SPF, DKIM, and DMARC alignment.",
        "raw_eml": """Delivered-To: faculty@college.ac.in
Received: by 103.141.51.10 with SMTP id nic_relay_in;
        Tue, 22 Sep 2026 10:00:15 +0530 (IST)
Received: from mail.nic.in (mail.nic.in [103.27.8.44])
        by mx.college.ac.in with ESMTP id 44B901C2;
        Tue, 22 Sep 2026 04:30:00 +0000
Authentication-Results: college.ac.in;
        spf=pass (mail.nic.in: domain of aicte-india.org designates 103.27.8.44 as permitted sender);
        dkim=pass (signature verified);
        dmarc=pass (p=reject)
Received-SPF: pass (aicte-india.org: domain designates 103.27.8.44 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=aicte-india.org; s=202601;
        bh=k4l3m2n1o0p9q8r7s6t5u4v3w2x1y0z=;
        b=AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789=
From: "AICTE Media & Academic Cell" <noreply@aicte-india.org>
To: "All Approved Technical Institutions" <all-colleges@aicte-india.org>
Return-Path: <noreply@aicte-india.org>
Subject: Announcement: National Faculty Development Program on Cybersecurity & Cloud Forensics 2026
Date: Tue, 22 Sep 2026 10:00:00 +0530
Message-ID: <circular.2026.09.22.8871@aicte-india.org>
Content-Type: text/plain; charset="UTF-8"

Greetings from All India Council for Technical Education (AICTE),

We are pleased to announce the schedule for the two-week National Faculty Development Program (FDP) on Cybersecurity, Incident Response, and Digital Forensics scheduled for October 2026.

Faculty members can register online through the official AICTE ATAL Academy portal:
https://www.aicte-india.org/atal

Participation is free of cost for faculty of AICTE approved colleges. For queries, contact fdp-support@aicte-india.org.

Regards,
Directorate of Academic Planning, AICTE
Nelson Mandela Marg, Vasant Kunj, New Delhi-110070
"""
    }
}
