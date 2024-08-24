---
layout: page
title: A propos
permalink: /about/
weight: 5
---

# **A mon sujet**

Bonjour ! Je suis **{{ site.author.name }}** :wave:,<br>

>Si l'envie vous venait de vouloir me contacter par e-mail, vous noterez que j'utilise une adresse *étrange* `@duck.com`.
>Il s'agit d'un alias fourni par **DuckDuckGo** (plus connu pour son navigateur) qui permet de cacher ma véritable adresse mail, et que je peux facilement désactiver et renouveler en cas de spam sur cette adresse.
>Après tout, il s'agit d'un blog orienté cybersécurité, commencer par ne pas dévoiler une adresse personnelle au monde entier est un bon début <i class="fas fa-user-secret fa-beat-fade" style="--fa-animation-duration: 2s;"></i>

<div class="row">
{% include about/skills.html title="Programmation" source=site.data.programming-skills %}
{% include about/skills.html title="Autres Compétences" source=site.data.other-skills %}
</div>

<div class="row">
{% include about/timeline.html %}
</div>
