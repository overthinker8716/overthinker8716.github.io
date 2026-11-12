title: [FR] La pile que le noyau ne peut pas écrire
date: 2026-11-12

Il y a un point sur lequel je bloquais en lisant sur CET côté noyau sous Windows. Le modèle de menace du noyau part du principe que l'attaquant a déjà une écriture arbitraire. La shadow stack doit donc être impossible à écrire depuis le ring 0. Sauf que chaque `call` du noyau écrit dedans. Avec une pagination classique, les deux ne tiennent pas ensemble, et j'ai mis un moment à voir où était l'astuce.

Ce sont mes notes. L'essentiel vient du reverse d'autres personnes, les liens sont en bas.

## Ce que CET apporte, et ce qu'il n'apporte pas

Petit rappel. Avec CET activé (bit 23 de `CR4`, plus le bit 0 de `IA32_S_CET`, MSR `0x6A2`), les adresses de retour sont empilées deux fois : une fois sur la pile normale, une fois sur une seconde pile pointée par `SSP`. En ring 0, ce pointeur vient de `IA32_PL0_SSP` (`0x6A4`).

```c
void ret(void)
{
    uint64_t expected = shadow_pop(ssp);
    uint64_t actual = pop(rsp);

    if (actual != expected)
        raise(CONTROL_PROTECTION_FAULT, NEAR_RET);

    rip = actual;
}
```

On écrase une adresse de retour, on récolte un `#CP` au lieu d'une chaîne ROP. Très bien.

Maintenant, comment le CPU sait qu'une page est une shadow stack ? Par la PTE : présente, non inscriptible, dirty. Une combinaison qui n'a aucun sens autrement.

```c
bool is_shadow_stack_page(PTE pte)
{
    return pte.present && !pte.write && pte.dirty;
}
```

Un `mov` ordinaire vers cette page provoque une faute. En mode utilisateur l'histoire s'arrête là, les tables de pages sont hors de portée.

Dans le noyau, tout seul, ça ne sert à rien. Les PTE sont de la mémoire noyau. Avec une primitive d'écriture je passe `R/W` à 1, je modifie l'adresse de retour, je remets le bit à 0. Ou alors je ne m'embête même pas avec les permissions et je fais pointer la PTE vers une page physique que je contrôle. Satoshi Tanda détaille les deux dans son article et je ne vois pas de troisième option qui vaille la peine.

Donc ce qui protège la shadow stack ne peut pas se trouver dans les tables de pages de l'invité.

## Le bit 60

HVCI donne déjà à Windows un endroit auquel le noyau ne peut pas toucher : l'EPT, qui appartient à l'hyperviseur. Première idée, y marquer les pages de shadow stack en lecture seule.

Ça ne marche pas, et c'est ce que j'avais raté. Un `call` écrit dans la page. Lecture seule dans l'EPT, ça veut dire une violation EPT, donc un VM exit, à chaque instruction call du noyau. Personne ne livre ça.

Intel a ajouté un bit exactement pour ce cas. Si le bit 7 de l'EPTP est à 1, le bit 60 d'une entrée finale signifie « page de shadow stack superviseur ».

```c
typedef union _EPT_LEAF {
    uint64_t value;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t large_page : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t user_execute : 1;
        uint64_t : 1;
        uint64_t frame : 40;
        uint64_t : 5;
        uint64_t verify_guest_paging : 1;
        uint64_t paging_write : 1;
        uint64_t : 1;
        uint64_t supervisor_shadow_stack : 1;
        uint64_t sub_page_write : 1;
        uint64_t : 1;
        uint64_t suppress_ve : 1;
    };
} EPT_LEAF;
```

La page est mappée avec `write = 0` et `supervisor_shadow_stack = 1`. Les accès de type shadow stack passent sans exit. Les écritures de données tombent sur `write = 0` et meurent là, quoi que dise la PTE de l'invité.

Ça règle aussi l'attaque par remappage, par l'autre bout : un accès shadow stack n'est autorisé que sur une page qui porte le bit. Faites pointer la PTE vers votre propre page et le prochain `call` plante, parce que votre page n'est pas marquée.

AMD a l'équivalent (SSSCheck), encodé autrement dans les tables de pages imbriquées. Je ne l'ai pas regardé de près.

## NT ne peut plus allouer ses propres piles

Seul VTL1 peut demander à l'hyperviseur de changer ce que voit VTL0. Créer un thread implique donc maintenant le Secure Kernel :

```text
nt!PspAllocateThread
  nt!KeInitThread
    nt!KiCreateKernelShadowStack
      nt!MmCreateKernelStack
        nt!MiAllocateKernelStackPages
          nt!VslAllocateKernelShadowStack
            ======== secure call ========
            securekernel!SkmmCreateNtKernelShadowStack
              securekernel!SkmiClaimPhysicalPage
                HvCallModifyVtlProtectionMask
              securekernel!SkmiInitializeNtKernelShadowStack
```

Ces noms viennent de l'article de Connor McGarr et bougeront d'un build à l'autre.

Ce qui me plaît ici, c'est l'ordre des opérations. Le Secure Kernel prend les pages, retire l'accès en écriture à VTL0, les met à zéro, puis écrit lui-même le contenu initial (le token en haut, et l'adresse où le thread démarre). Il n'y a jamais de fenêtre où NT a la page mappée en écriture.

Un secure call par création de thread, c'est lent, donc les shadow stacks libérées sont gardées en cache par processeur et par nœud NUMA, toujours protégées.

## La partie qui a l'air fragile

`ret` n'est pas la seule façon de sortir d'une fonction. Les exceptions, le déroulement de pile, la restauration d'un `CONTEXT` : tout ça laisse `SSP` pointer sur des frames qui n'existent plus. Et NT ne peut pas réparer une pile qu'il ne peut pas écrire. Alors il demande :

```text
nt!KeKernelShadowStackRestoreContext
  nt!VslKernelShadowStackAssist
    ======== secure call ========
    securekernel!SkmmNtKernelShadowStackAssist
      securekernel!SkmiNtKssAssistDispatch
        securekernel!SkmiNtKssAssistRestore
```

VTL1 compare le `SSP` qu'on lui demande de positionner avec ce qu'il sait de la shadow stack de ce thread, puis le positionne via l'hyperviseur.

Si je cherchais des bugs, je commencerais par là. On ne peut pas écrire la shadow stack, mais on peut demander à VTL1 de déplacer le pointeur à notre place, et tout repose sur la rigueur de cette vérification. McGarr mentionne aussi dans son talk Black Hat que sur un `#CP`, le handler cherche la mauvaise adresse de retour plus bas dans la shadow stack et continue s'il la trouve. Je ne l'ai pas reproduit et je ne sais pas encore quelle marge ça laisse. C'est la prochaine chose que je veux regarder.

## Est-ce activé ?

Pas par défaut la dernière fois que j'ai vérifié, et il faut HVCI. Les réglages sont ici :

```powershell
$scenarios = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
Get-ItemProperty "$scenarios\HypervisorEnforcedCodeIntegrity", "$scenarios\KernelShadowStacks"
```

## À lire

- Connor McGarr, [Out Of Control: KCFG and KCET](https://i.blackhat.com/BH-USA-25/Presentations/USA-25-McGarr-Out-Of-Control-KCFG-And-KCET.pdf) (Black Hat USA 2025) et son [article sur les shadow stacks en mode noyau](https://connormcgarr.github.io/km-shadow-stacks)
- Satoshi Tanda, [What keeps kernel shadow stack effective against kernel exploits?](https://tandasat.github.io/blog/2025/04/02/sss.html)
- Aulnette et Jullian, [Windows kernel shadow stack mitigation](https://www.sstic.org/media/SSTIC2025/SSTIC-actes/windows_kernel_shadow_stack_mitigation/SSTIC2025-Article-windows_kernel_shadow_stack_mitigation-aulnette_jullian.pdf) (SSTIC 2025)
