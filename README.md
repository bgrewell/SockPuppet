# Sock Puppet

## Purpose

Sock Puppet is a tool for creating custom snaps that execute user specified commands or shell scripts using the `dirty sock` vulnerability in the snapd api.
This tool works by taking the users specified command or script and packaging it as a snap (essentially just a squashfs with some meta files) and uses the install hook like Chris Moberly's original code to execute the commands under the context of root. 

```
vulnerable versions:
  start: 2.28
  end: 2.37
  
tags:
  - Dirty Sock
  - snapd
  - usn-3887-1
  - chris moberly
  - cve-2019-7304
