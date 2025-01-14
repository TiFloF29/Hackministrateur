---
layout: page
title: A propos
permalink: /about/
weight: 5
---

# **A mon sujet**

Bonjour ! Je suis **{{ site.author.name }}** :wave:

Bien qu'ayant étudié dans le domaine de l'automobile jusqu'en 2016, puis travaillé en tant que motoriste pendant 4 ans, j'ai décidé de changer de voie, vers l'administration des systèmes informatiques. Un défi n'arrivant jamais seul, j'ai également entamé des formations en cybersécurité comme [TryHackMe](https://tryhackme.com/), [HackTheBox](https://www.hackthebox.com/) et son Academy, [RootMe](https://www.root-me.org/) ou encore [Hackropole](https://hackropole.fr/fr/) de l'ANSSI.

Pour un apprentissage plus global de l'informatique, je pratique également la programmation sur la plateforme [CodinGame](https://www.codingame.com/).

Professionnellement, j'utilise également des plateformes comme Coursera et Udemy grâce à un plan de formation mis à disposition par l'entreprise pour laquelle je travaille actuellement.

Et puisque ça ne suffisait pas, j'ai dû découvrir Github, Jekyll, HTML, CSS pour mettre en place ce site. Certes, le thème utilisé a été développé par [Yousinix](https://github.com/yousinix/portfolYOU), mais il m'a fallu tordre quelques fichiers pour que le site ressemble à ce que je voulais réellement. C'est aussi ça la magie de l'*open-source* : pouvoir partir d'un projet existant, et l'adapter à ses goûts (dans le respect des licences, et du matériel original bien entendu).

Terminons cette présentation par remercier celui sans qui ce site aurait été moins personnalisé : ChatGPT 4o !

> Si l'envie vous venait de vouloir me contacter par e-mail, vous noterez que j'utilise une adresse *étrange* `@duck.com`.
> Il s'agit d'un alias fourni par **DuckDuckGo** (plus connu pour son navigateur) qui permet de cacher ma véritable adresse mail, et que je peux facilement désactiver et renouveler en cas de spam sur cette adresse.
> Après tout, il s'agit d'un blog orienté cybersécurité, commencer par ne pas dévoiler une adresse personnelle au monde entier est un bon début <i class="fas fa-user-secret fa-beat-fade" style="--fa-animation-duration: 2s;"></i>

<div class="row">
{% include about/skills.html title="Informatique" source=site.data.computer-skills %}
{% include about/skills.html title="Outils Cybersécurité" source=site.data.cyber-skills %}
</div>

<div class="row">
{% include about/skills.html title="Programmation" source=site.data.programming-skills %}
{% include about/skills.html title="Passions" source=site.data.passions %}
</div>

<div class="row">
{% include about/timeline.html %}
</div>
