---
name: L'histoire de ce site
tools: [Personnalisation]
image: "https://cdn.pixabay.com/photo/2021/10/08/18/55/website-6692147_960_720.png"
description: Pourquoi je me suis décidé à faire mon site internet, et comment ?
---

# L'histoire du site

## 1. Pourquoi un site ?

Lorsque j'ai commencé à me former en informatique, je recherchais un moyen didactique de prendre des notes. J'avais alors commencé par un site Google, mais je me suis senti limité par l'interface.

J'envisageais donc de rédiger des contenus en Markdown que j'aurais pu stocker dans un dépôt Github. Mais il était impossible d'avoir un style personnalisé.

Lorsque j'étais en quête d'information sur comment réaliser certains défis sur TryHackMe, j'arrivais souvent sur des sites "github.io" sans trop savoir la différence avec son équivalent ".com". C'est en cherchant des informations sur le sujet que j'ai découvert qu'on pouvait simplement et gratuitement héberger un site dans un dépôt Github. Certes le site statique, mais il est personnalisable et facile à mettre en oeuvre.

## 2. Des débuts timides

Disons le : je me suis lancé tête baissée, me basant sur le peu d'informations que j'avais lu. Et ça n'a pas marché.

J'ai donc suivi le [tutoriel sur les sites *Github Pages*](https://github.com/skills/github-pages) pour comprendre comment fonctionne concrètement l'outil, comment s'articulent les différents éléments.

Après le tutoriel, je suis parti à la recherche du [thème](https://github.com/topics/jekyll-theme) qui habillera mon site. J'ai simplement suivi les consignes du développeur qui l'a partagé, et il ne me restait plus qu'à créer le contenu.

>Un site clé en main, c'est bien ; mais un site qui me ressemble, c'est mieux.

Je me suis donc lancé dans la personnalisation de l'aspect de mon projet. Création de nouvelles pages, utilisation de plus de couleurs, amélioration des éléments existants...

## 3. Nouvelles pages et système de filtre

Le thème initial [portfolYOU](https://github.com/yousinix/portfolYOU) dispose d'une page pour des projets, et d'une autre recensant les posts de blog. Je cherchais un moyen de filtrer les posts grâce aux tags et faciliter la recherche des comptes-rendus en fonction des plateformes (THM, HTB, RootMe...).

Puisque la simple recherche par tags ne fonctionnait pas malgré l'aide de l'IA, j'ai opté pour l'adaptation de la page de blog originale pour permettre de n'afficher que les posts disposant du même tag que la page.

Les pages filtrées sont accessibles par un système de boutons.

Les sites hébergés par Github fonctionnant avec le moteur Jekyll, le langage Liquid est pris en compte. Le bloc permettant de filtrer le contenu est :

```html
<div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4 m-4 mt-5">
  {% assign filtered_posts = site.posts | where: "tags", page.tags %}
  
  {% for post in filtered_posts %}
    {% include blog/post-card.html %}
  {% endfor %}
</div>
```

<div class="text-center">
<i class="fa-solid fa-1xl text-info">Redaction en cours</i><br />
<i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-info mt-3"></i>
</div>
