---
name: Discussion
about: Any other content that doesn't fit in the other templates
title: ''
labels: 'discussion'
assignees: ''

---

## Summary

> A short description of what it is. (Required)

Example:

> Provide a solver which can solve from previously configured DNS records.

## Goals

> What is supposed to do in short. (Optional)

Example

> A simple, static DNS server

## Non-Goals

> What people would think it is supposed to do, but it is not? (Optional)

Example
> * Not to implement a full and complex DNS server

## Motivation

> Why it's a feature to be considered? (Required)

Example:

> People can use DPS for static DNS entries instead of use /etc/hosts or something like.

## Description

> Explain the feature details and how it would work, usecases, examples, snippets of code,
> inputs and outputs, etc. (Required)

Example

> ### Storage
>
> DNS records will be stored at the existing DPS config file.
>
> ### DNS Records 
> * It will have support to A, AAAA and CNAME entries.
> * Also, TTL by record will be supported
