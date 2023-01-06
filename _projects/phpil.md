---
layout: page
title: PuzzIL
description: An intermediate language fuzzer for PHP
importance: 1
category: work
---

[PuzzIL](https://github.com/jkrshnmenon/phpil) (pronounced like "puzzle") is an intermediate language fuzzer for the PHP based on top of [PhpIL](https://github.com/teambi0s/phpil).

I was a part of team airspace for the course CSE 598 : Applied Vulnerbility Research that was offered at [Arizona State University](https://www.asu.edu/) by [Dr. Yan Shoshitaishvili](https://yancomm.net/) during the Spring 2021 semester. In this course, the students were separated into multiple groups and each group was to select a relatively popular application and find vulnerabilities in it. Our team airspace chose the PHP language as our target.

At the time, [PHP 8.0](https://www.php.net/releases/8.0/en.php) had just rolled out its own Just-In-Time (JIT) compiler and it was a lucrative target for fuzzing.

However, there did not exist any fuzzers that targeted PHP except for PhpIL which only had the very basic functionality required for a fuzzer.
PhpIL itself was borrowing the idea from [Fuzzili](https://github.com/googleprojectzero/fuzzilli) which was the best fuzzer for fuzzing JavaScript engines.

We implemented an executor, coverage tracking and builtin function fuzzing support and created our own version of PHP IL fuzzer and used it to target the JIT engine in PHP 8.0
We found two bugs ([NULL Dereference](https://bugs.php.net/bug.php?id=80958) and [DOS](https://bugs.php.net/bug.php?id=80959)) after running multiple instances of the fuzzer for 24 hours.
We triaged these bugs and reported them to the PHP developers, however the bugs were not assigned a CVE due to the fact that their security impact was very little.

PuzzIL lacks a proper mutation engine which could be something improved in the future.
But we certainly had fun creating this fuzzer.

Our final presentation for this class can be found on [YouTube](https://www.youtube.com/watch?v=RbST0FByvV8&t=8597s).
