---
title: "Building Trial Ledger with Devin Bots"
published: 2026-11-19
description: "A plan for tracking software trials, reviewing term changes, and keeping calendar reminders up to date."
tags: ["Devin Bots", "Projects"]
lang: "en"
draft: false
---

A trial offer can disappear before I claim it, and the terms on a public page can differ from the dates in my signup confirmation. I’m building Trial Ledger to track those dates and put the right reminder on my calendar. The tracker will run locally on my Mac, and I’ll use this site to share the build and demo.

**Status** · Project brief published. Implementation and Devin Bots connection are pending.

## First release

1. Add an official offer URL, paste a redemption confirmation, and record whether the offer is available, claimed, or ended.
2. Check the public terms daily. Use TypeScript to parse the terms, SQLite to record changes, and Playwright for pages that require JavaScript to render. Store each candidate change with the source URL, a relevant text excerpt, and the time it was observed.
3. Review proposed changes to dates and prices. Dates supplied with a time zone retain that zone. Ambiguous dates stay in review. An approved change updates the same calendar reminder using a stable iCalendar UID.

## First three test sources

| Service | What the test should verify |
| --- | --- |
| [Apple Music Individual (US)](https://www.apple.com/apple-music/) | Distinguish the Individual offer from the Family, Student, and device offers. Use the confirmed renewal date to schedule the reminder. |
| [JetBrains IntelliJ IDEA Ultimate](https://www.jetbrains.com/help/idea/register.html) | Calculate the 30-day window from the first-launch date and identify the switch to free features after expiry. |
| [Google Cloud Free Trial](https://docs.cloud.google.com/free/docs/free-cloud-features) | Track the 90-day time limit and the possibility of earlier expiry when credits run out. The remaining balance is entered manually. |

## Devin Bots setup

1. After Devin Bots access is available, connect GitHub in Devin and select `mxym/mxym.github.io` for the project. The initial work will add the tool in a self-contained project directory in this repository. [Devin docs](https://docs.devin.ai/)
2. Give the Bot an initial GitHub issue to build the offer importer and parser tests for the three sources using saved excerpts as fixtures. The Bot opens a pull request with test results for maintainer review.
3. Set up the maintenance workflow once the importer is running. After repeated parse failures, the tracker should open or update one GitHub issue per affected source with the URL, error, and relevant public excerpt. Route those issues to the Bot to update the parser, add a regression test, and open a pull request. The maintainer reviews and merges changes.

Redemption confirmations and account-specific balances stay on the Mac. Parser issues and fixtures use public source material.

## First demo

Import all three sources, simulate a change to one trial deadline, approve the change in the review screen, and verify that the calendar export keeps the original event UID with the updated date.
