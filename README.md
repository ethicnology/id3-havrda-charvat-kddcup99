# Intrusion detection and classification using improved ID3 algorithm of data mining

## Faire la synthèse de l'article.

L’article est une publication de Sandeep Kumar et Satbir Jain nommée, *Intrusion Detection and Classification Using Improved ID3 Algorithm of Data Mining* ,elle traite de la Détection des intrusions et de leur classification en utilisant une version modifiée de l’algorithme ID3.

Dans l’introduction, les auteurs définissent la détection d’intrusion comme étant le processus d’identification des actions qui portent atteinte à la confidentialité, l’intégrité ou la disponibilité des ordinateurs ou des réseaux. Après un constat sur l’augmentation du taux d’intrusion annuel, ils présentent la notion d’IDS ou *Intrusion Detection System*, ces systèmes utilisent la comparaison avec les signatures d’attaques enregistrées dans une base de données. Les auteurs énoncent les inconvénients de cette méthode car elle nécessite une mise à jour régulière des signatures et ne peut pas détecter des attaques qui ne sont pas encore connues.

Pour améliorer l’efficience des systèmes, les auteurs proposent la notion d’arbre de décision. Un arbre de décision est une méthode qui permet, à partir d’un ensemble de données classifiées, de déduire les règles qui ont permis leur classification. Une fois l’arbre conçu, le système peut effectuer des prédictions sur la classification de nouvelles données.

L’algorithme ID3 est majoritairement utilisé parmi les arbres de décision, il est développé par Ross Quinlan en 1986. Dans leur proposition d’approche, les auteurs expliquent le fonctionnement de l’algorithme ID3 et mettent en valeur le calcul de l’entropie de Shannon. L’entropie est le concept utilisé pour quantifier le désordre dans un ensemble de données. Lorsque toutes les données d’un ensemble appartiennent à la même catégorie, il n’y a pas d'incertitude, l’entropie vaut zéro. Les auteurs proposent de substituer l’entropie de Shannon par une entropie de Havrda-Charvat pour obtenir de meilleurs résultats et réduire la complexité algorithmique. La formule de l’entropie selon Havrda et Charvat est la suivante :  
<img title="Havrda-Charvat entropy" src="https://github.com/ethicnology/id3-havrda-charvat-kddcup99/blob/main/images/Havrda-Charvat-entropy.png?raw=true" alt="entropy">

Pour valider cette nouvelle méthodologie de calcul, les auteurs établissent un protocole d'expérimentation qui se base sur l’utilisation d’un ensemble de données normées concernant les intrusions réseaux. Ces données sont collectées par la DARPA et le MIT sous le nom de KDDcup99 en 1999.  
Ce jeu de données contient approximativement 5 millions d’instances. Chaque ligne correspond à une requête. Pour chacune des lignes on trouve 42 valeurs qui détaillent les différents paramètres des requêtes. A chaque fin de ligne, on trouve une valeur nommée *target* qui classifie la requête en attaque ou pas. Dans le cadre du jeu de données initial, les requêtes sont classées en 5 catégories : *normal* puis quatre catégories d’attaques (*DoS*, *U2R*, *R2L* et *probe*). 

L'expérimentation est menée grâce au logiciel MATLAB, sur un échantillon correspondant à 10% de KDDcup99. Ils utilisent ensuite l’algorithme ID3 dont l'entropie est modifiée afin de construire leur modèle prédictif. Les résultats de cette expérimentation montrent une précision dans la classification de 97.74% et un taux d’erreur de 2.81%. Pour conclure, cette publication tend à démontrer la pertinence de l’usage d’une entropie de Havrda et Charvat dans la modélisation d’un arbre de décision selon algorithme ID3 pour la détection d’intrusion sur le jeux de données KDDcup99.

## Explorer l'algorithme ID3 de Weka avec quelques échantillons de données. Pour l'expérimentation, vous pouvez utiliser le dataset du site du cours ou celui du site officiel.

Nous avons utilisé différents échantillons de KDDcup99, le premier est fournit dans le cours et contient quinze *features*, le second provient du site [OpenML](https://www.openml.org) et possède quarante-deux *features*. Pour utiliser l'arbre de décision ID3 dans Weka, il a fallu discretiser les *features* numériques en valeurs nominales. Nous avons également agrégé les classifications d'attaque sous une seule entité "*attack*". L'ensemble des expérimentations a été réalisé selon une répartition de ⅔ de l’échantillon pour l'entraînement du modèle et ⅓ pour le tester.

## Quel est votre constat quant aux résultats obtenus avec ID3 ?

Les résultats obtenus sont très convaincants avec un taux de classification correct de 99.9433%.  Il est aussi important de noter le faible taux d’erreur avec 0.0385% ainsi que le faible taux de données que le modèle n’a pas su classer 0.0182%. Nos résultats sont supérieurs à ceux mentionnés dans la publication, le chercheur n'ayant pas annexé son implémentation, elle est probablement différente de celle de Weka, plus performante.
![](https://github.com/ethicnology/id3-havrda-charvat-kddcup99/blob/main/images/KDDcup99-sample-Shannon.png)

## Modifier l'algorithme ID3 en utilisant l'entropie de Havrda et Charvat décrite dans l'article "Intrusion detection and classification using improved ID3 algorithm of data mining".

L'article propose de substituer le calcul de l'entropie de l'algorithme ID3 par celui de Havrda et Charvat. Pour ce faire, nous avons modifié la méthode *computeEntropy* nécessaire pour calculer le gain d'information.

```java
  /**
   * Computes the entropy of a dataset.
   * 
   * @param data the data for which entropy is to be computed
   * @return the entropy of the data's class distribution
   * @throws Exception if computation fails
   */
  private double computeEntropy(Instances data) throws Exception {
    double [] classCounts = new double[data.numClasses()];
    Enumeration instEnum = data.enumerateInstances();
    double numAttributes = 0;
    while (instEnum.hasMoreElements()) {
      Instance inst = (Instance) instEnum.nextElement();
      classCounts[(int) inst.classValue()]++;
      numAttributes++;
    }
    double entropy = 0;
    for (int j = 0; j < data.numClasses(); j++) {
      if (classCounts[j] > 0) {
        entropy += Math.pow(classCounts[j]/numAttributes, getAlpha());
      }
    }
    entropy = (1.0/(Math.pow(2.0, 1.0-getAlpha())-1.0))*(entropy-1.0);
    return entropy;
  }
```

## Expérimenter cette nouvelle implémentation en utilisant le même dataset. Expliquez comment vous avez mené les tests.

Nous commençons par charger l'échantillon de 10% de KDDcup99 dans Weka. Nous discrétisons les *features* numériques et nous agrégeons les différentes classifications d'attaques sous une seule, "*attack*". L'ensemble des expérimentations sont réalisées selon une répartition de ⅔ de l’échantillon pour l'entraînement du modèle et ⅓ pour tester le modèle. Nous sélectionnons notre version modifiée d'ID3 et nous paramétrons, grâce à l'interface graphique, différentes valeurs de alpha.

Pour le challenge, nous avons également entrepris des tests sur le dataset complet de KDDcup99, il a fallu l'adapter pour weka (annotations .arff) puis procéder à la discrétisation du fichier de cinq millions d'instances. La discrétisation a conduit à des crash de l'application (*out of memory*) et, après plusieurs tentatives, nous avons dû augmenter la mémoire allouée à Weka jusqu'à 11Go couronné de succès.  
![](https://github.com/ethicnology/id3-havrda-charvat-kddcup99/blob/main/images/KDDcup99-full-Havrda-Charvat.png)

## Est-ce-que vous avez obtenu les mêmes résultats que l'article ? Si ce n'est pas le cas, justifiez votre réponse ? Expliquez pourquoi cette nouvelle entropie d'Havrda et Charvat donne une meilleure solution ?

L'article mentionne les résultats suivants : "The accuracy of proposed system is 97.74 % and Error Rate is 2.81%", nous n'obtenons pas les mêmes résultats. A partir de l'échantillon initial, les résultats obtenus ont un taux de classification correct de 99.944%, un taux d’erreur de 0.0391% ainsi qu'un taux de données que le modèle n’a pas su classer de 0.0169%. 

La différence résultat provient de différents facteurs :

- La différence dans l'implémentation de l'algorithme ID3 entre les auteurs de la publication et celle de Weka

- Les auteurs de la publication agrègent les 22 classifications d'attaques en 4 catégories alors que nous n'en faisons qu'une.

![](https://github.com/ethicnology/id3-havrda-charvat-kddcup99/blob/main/images/KDDcup99-sample-Havrda-Charvat.png)

L'implémentation de l'entropie d'Havrda-Charvat démontre de meilleurs résultats que celle de Shannon, outre l'optimisation des performances d'exécution, l'article ne spécifie pas ce qui rend cette entropie plus adaptée. Nous avons donc procédé à la recherche d'autres publications et pour trouver une réponse en faveur de l'entropie de Havrda-Charvat.

L’entropie de Tsallis est introduite en 1988 par Constantino Tsallis généralise en physique une forme identique à celle de Havrda-Charvat. Tsallis est une autre appellation pour l'entropie de Havrda-Charvat qui nous a permis de trouver plus de publications sur le sujet.

La publication *Comparison of Shannon, Renyi and Tsallis Entropy used in Decision Trees* de <u>Tomasz Maszczyk et Wlodzislaw Duch</u> compare les caractéristiques de différents calculs d'entropie, deux citations ont retenu notre attention : 

- “It has similar properties as the Shannon entropy:
  – it is additive 
  – it has maximum = ln(n) for p i = 1/n
  but it contains additional parameter α which can be used to make it more or less sensitive to the shape of probability distributions.”

- “This algorithm makes it more attractive than standard approach based on Shannon entropy that does not allow for exploration of the tradeoff between the probability of different classes and the overall information gain.”

Nous pouvons donc considérer que grâce au paramètre alpha, l'entropie de Havrda-Charvat peut être plus précise que celle de Shannon, puisqu'il permet le compromis entre la probabilité de différentes classes et le gain d'information. 

## Quelle est la valeur optimale du paramètre alpha. Expliquez comment vous avez procédé pour obtenir cette valeur ?

Pour une répartition de ⅔ de l’échantillon pour l'entraînement du modèle et ⅓ pour le tester, la valeur optimale du paramètre alpha est **0.5**. Pour obtenir cette valeur nous avons procédé à la variation du paramètre alpha par cran de 0.1 entre les valeurs 0.1 et 0.9.

## Bonus : Vous pouvez aussi fournir une interface graphique pour le réglage de l'algorithme.

Pour fournir une interface graphique qui permet de régler le paramètre alpha de l'algorithme, nous nous sommes inspiré de l'implémentation de J48 de Weka.

```java
  /** Needed to compute Havrda-Charvat entropy  */
  protected double alpha = 0.5;

  public void setAlpha(double init_alpha) {
    alpha = init_alpha;
  }

  public double getAlpha() {
    return alpha;
  }

  @Override
  public Enumeration<Option> listOptions() {
    Vector<Option> newVector = new Vector<Option>(1);
    newVector.addElement(new Option("\tAlpha parameter", "A", 0, "-A"));
    newVector.addAll(Collections.list(super.listOptions()));
    return newVector.elements();
  }

  @Override
  public void setOptions(String[] options) throws Exception {
    String str = Utils.getOption("A", options);
    double init_alpha = Double.parseDouble(str);
    if(str.equals("") || init_alpha <= 0.0 || init_alpha == 1.0){
      setAlpha(0.5);
      throw new Exception("Set alpha > 0 and != 1");
    }else{
      setAlpha((new Double(init_alpha)).doubleValue());
    }
    super.setOptions(options);
    Utils.checkForRemainingOptions(options);
  }

  @Override
  public String [] getOptions(){
    Vector<String> options = new Vector<String>();
    options.add("-A");
    options.add("" + getAlpha());
    Collections.addAll(options, super.getOptions());
    return options.toArray(new String[0]);
  }
```
