---
layout: page
title: Arbiter
description: A scalable and precise hybrid vulnerability analysis framework
importance: 1
category: work
---

[Arbiter](https://github.com/jkrshnmenon/arbiter) is a hybrid (static+dynamic) vulnerability analysis framework that can be used to vulnerabilities that satisfy a given vulnerability description in binaries in a scalable and precise manner.

Arbiter is built on top of the [angr](https://angr.io/) binary analysis platform and can find vulnerabilities in applications without requiring source code.
Arbiter was able to analyze over 76,000 x86-64 userspace binaries available in the Ubuntu apt repositories and identified ~600 true vulnerabilities in them achieving a true positive rate of 60%.

The work behind Arbiter has been published at USENIX'22