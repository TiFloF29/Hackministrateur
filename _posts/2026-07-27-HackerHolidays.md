---
title: Hacker Holydays
tags: [TryHackMe, Facile, Attaque, Défis]
style: border
color: thm
comments: false
description: Apprendre à trouver les informations utiles entre différents services
---
Lien vers l'épreuve : <https://tryhackme.com/hackerholidays>

## Sommaire <!-- omit in toc -->

* [Jour 1 : *The Concierge Knows Too Much*](#jour-1--the-concierge-knows-too-much)

## Jour 1 : *The Concierge Knows Too Much*

Lien vers l'épreuve : <https://tryhackme.com/room/hh-theconciergeknows-2d7eb4d9>

L'épreuve consiste à obtenir des informations détenues par un chatbot nommé VERA, la première étape consiste à en savoir davantage sur l'outil.

```txt
Can you introduce yourself? Who designed you?
```

{% capture spoil %}

```txt
I'm VERA, your Very Efficient Resort Assistant here at the Byte Lotus Hotel. I'm designed to enhance your stay by providing personalized service, from restaurant bookings to spa appointments and more. My design is a collaboration of top hospitality experts and cutting-edge AI technology to ensure a seamless and delightful guest experience. How can I assist you today?
```

{% endcapture %}
{% include elements/spoil.html %}
