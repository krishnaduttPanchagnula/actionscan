## Security Blog

The latest news and insights from Google on security and safety on the Internet

## Announcing OSV-Scanner: Vulnerability Scanner for Open Source

December 13, 2022

Posted by Rex Pan, software engineer, Google Open Source Security Team

Today, we’re launching the OSV-Scanner, a free tool that gives open source developers easy access to vulnerability information relevant to their project.

Last year, we undertook an effort to improve vulnerability triage for developers and consumers of open source software. This involved publishing the Open Source Vulnerability (OSV) schema and launching the OSV.dev service, the first distributed open source vulnerability database. OSV allows all the different open source ecosystems and vulnerability databases to publish and consume information in one simple, precise, and machine readable format.

The OSV-Scanner is the next step in this effort, providing an officially supported frontend to the OSV database that connects a project’s list of dependencies with the vulnerabilities that affect them.

# OSV-Scanner

Software projects are commonly built on top of a mountain of dependencies—external software libraries you incorporate into a project to add functionalities without developing them from scratch. Each dependency potentially contains existing known vulnerabilities or new vulnerabilities that could be discovered at any time. There are simply too many dependencies and versions to keep track of manually, so automation is required.

Scanners provide this automated capability by matching your code and dependencies against lists of known vulnerabilities and notifying you if patches or updates are needed. Scanners bring incredible benefits to project security, which is why the 2021 U.S. Executive Order for Cybersecurity included this type of automation as a requirement for national standards on secure software development.

The OSV-Scanner generates reliable, high-quality vulnerability information that closes the gap between a developer’s list of packages and the information in vulnerability databases. Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners:

- Each advisory comes from an open and authoritative source (e.g. the RustSec Advisory Database)

Anyone can suggest improvements to advisories, resulting in a very high quality database

The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them

Running OSV-Scanner on your project will first find all the transitive dependencies that are being used by analyzing manifests, SBOMs, and commit hashes. The scanner then connects this information with the OSV database and displays the vulnerabilities relevant to your project.

OSV-Scanner is also integrated into the OpenSSF Scorecard’s Vulnerabilities check, which will extend the analysis from a project’s direct vulnerabilities to also include vulnerabilities in all its dependencies. This means that the 1.2M projects regularly evaluated by Scorecard will have a more comprehensive measure of their project security.

# What else is new for OSV?

The OSV project has made lots of progress since our last post in June last year. The OSV schema has seen significant adoption from vulnerability databases such as GitHub Security Advisories and Android Security Bulletins. Altogether OSV.dev now supports 16 ecosystems, including all major language ecosystems, Linux distributions (Debian and Alpine), as well as Android, Linux Kernel, and OSS-Fuzz. This means the OSV.dev database is now the biggest open source vulnerability database of its kind, with a total of over 38,000 advisories from 15,000 advisories a year ago.

The OSV.dev website also had a complete overhaul, and now has a better UI and provides more information on each vulnerability. Prominent open source projects have also started to rely on OSV.dev, such as DependencyTrack and Flutter.

# What’s next?

There’s still a lot to do! Our plan for OSV-Scanner is not just to build a simple vulnerability scanner; we want to build the best vulnerability management tool—something that will also minimize the burden of remediating known vulnerabilities. Here are some of our ideas for achieving this:

- The first step is further integrating with developer workflows by offering standalone CI actions, allowing for easy setup and scheduling to keep track of new vulnerabilities.

Improve C/C++ vulnerability support: One of the toughest ecosystems for vulnerability management is C/C++, due to the lack of a canonical package manager to identify C/C++ software. OSV is filling this gap by building a high quality database of C/C++ vulnerabilities by adding precise commit level metadata to CVEs.

We are also looking to add unique features to OSV-Scanner, like the ability to utilize specific function level vulnerability information by doing call graph analysis, and to be able to automatically remediate vulnerabilities by suggesting minimal version bumps that provide the maximal impact.

VEX support: Automatically generating VEX statements using, for example, call graph analysis.

# Try out OSV-Scanner today!

You can download and try out OSV-Scanner on your projects by following instructions on our new website osv.dev. Or alternatively, to automatically run OSV-Scanner on your GitHub project, try Scorecard. Please feel free to let us know what you think! You can give us feedback either by opening an issue on our Github, or through the OSV mailing list.

 Google

#### No comments
 :

Post a Comment

 

 

 

## Labels

 

- #sharethemicincyber

- #supplychain #security #opensource

- AI Security

- android

- android security

- android tr

- app security

- big data

- biometrics

- blackhat

- C++

- chrome

- chrome enterprise

- chrome security

- connected devices

- CTF

- diversity

- encryption

- federated learning

- fuzzing

- Gboard

- google play

- google play protect

- hacking

- interoperability

- iot security

- kubernetes

- linux kernel

- memory safety

- Open Source

- pha family highlights

- pixel

- privacy

- private compute core

- Rowhammer

- rust

- Security

- security rewards program

- sigstore

- spyware

- supply chain

- targeted spyware

- tensor

- Titan M2

- VDP

- vulnerabilities

- workshop

 

## Archive

 

- 

 

2026

Apr

- Mar

- Feb

- Jan

- 

 

2025

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2024

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2023

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2022

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2021

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2020

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2019

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2018

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2017

Dec

- Nov

- Oct

- Sep

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2016

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2015

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2014

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- Apr

- Mar

- Feb

- Jan

- 

 

2013

Dec

- Nov

- Oct

- Aug

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2012

Dec

- Sep

- Aug

- Jun

- May

- Apr

- Mar

- Feb

- Jan

- 

 

2011

Dec

- Nov

- Oct

- Sep

- Aug

- Jul

- Jun

- May

- Apr

- Mar

- Feb

- 

 

2010

Nov

- Oct

- Sep

- Aug

- Jul

- May

- Apr

- Mar

- 

 

2009

Nov

- Oct

- Aug

- Jul

- Jun

- Mar

- 

 

2008

Dec

- Nov

- Oct

- Aug

- Jul

- May

- Feb

- 

 

2007

Nov

- Oct

- Sep

- Jul

- Jun

- May

## Feed

Follow @google

 Follow

Give us feedback in our Product Forums.

- Google

- Privacy

- Terms
