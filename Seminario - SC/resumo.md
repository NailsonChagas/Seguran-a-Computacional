### **1. Introdução**
O problema central que motiva este trabalho é a proteção dos "dados em uso". Enquanto a indústria consolida a proteção de dados em repouso (criptografia de disco) e em trânsito (criptografia de rede), os dados processados na memória RAM permanecem vulneráveis. A solução primária para fechar esse "ciclo da confiança" são os **TEEs** (*Trusted Execution Environments*). 

Inicialmente, a Intel lançou o SGX, que exigia a reescrita massiva dos códigos das aplicações, um processo caro e sujeito a erros. O mercado, portanto, demandou abordagens *lift-and-shift* (implantar aplicações legadas em ambientes seguros sem modificar o código original). Para o SGX, criaram-se camadas intermediárias (*runtimes*). Paralelamente, surgiram TEEs baseados em Máquina Virtual (VM), como o AMD SEV e o recém-lançado Intel TDX. 

**Objetivo:** Os autores buscam preencher uma lacuna na literatura científica realizando uma comparação empírica exaustiva de desempenho, custos e consumo de recursos entre essas tecnologias de ponta, sendo este um dos primeiros estudos independentes a avaliar o novo Intel TDX.

---

### **2. Contexto e Motivação (Conceitos Fundamentais)**
Para compreender as abordagens, é necessário definir o conceito de **TCB** (*Trusted Computing Base* - Base de Computação Confiável), que delimita as fronteiras dos componentes nos quais se deve confiar. O artigo contrasta dois modelos:

*   **Process-based TEE (Baseado em Processos - Intel SGX):** O isolamento ocorre em um compartimento chamado *enclave*. O TCB é minúsculo: confia-se apenas no processador e no código do enclave. O Sistema Operacional (SO) e o Hipervisor são considerados potenciais ameaças. A memória do enclave fica restrita a uma área rígida chamada **EPC** (*Enclave Page Cache*).
*   **Runtimes (Gramine e Occlum):** Para contornar a exigência de reescrever o código para o SGX, utilizam-se **LibOS** (*Library Operating Systems*). Eles rodam dentro do SGX e traduzem as instruções da aplicação. O **Gramine-SGX** otimiza o uso de memória alocando-a sob demanda e agrupando chamadas ao SO. O **Occlum-SGX** foca num isolamento interno extremo, utilizando **SFI** (*Software Fault Isolation*).
*   **VM-based TEE (Baseado em VM - AMD SEV e Intel TDX):** Criptografam fisicamente toda a memória de uma Máquina Virtual usando chaves vinculadas ao hardware. O TCB é maior, pois agora o Sistema Operacional Convidado (*Guest OS*) é considerado confiável. Em troca dessa segurança ligeiramente menor, entregam facilidade absoluta para rodar qualquer software.

---

### **3. Trabalhos Relacionados**
Os pesquisadores revisaram a literatura e notaram que estudos anteriores focavam apenas em comparar o SGX com o AMD SEV em nichos específicos, como Inteligência Artificial ou Computação de Alta Performance (HPC). Como o Intel TDX foi liberado ao público recentemente, nenhum estudo até o momento havia feito um *benchmark* cruzando todas as principais tecnologias modernas de nuvem frente a frente.

---

### **4. Metodologia**
Para garantir um teste justo, os autores usaram ferramentas rigorosas em servidores dedicados (*bare metal*) para evitar interferências da nuvem (*noisy neighbors*). 

*   **Hardware:** O Intel TDX, o SGX e os testes nativos (sem proteção, usados como base de comparação) rodaram em um processador Intel Xeon Platinum 8480C. O AMD SEV rodou em um AMD EPYC 7763v.
*   **Normalização Matemática:** A CPU da AMD operava com um *clock* inferior e era cerca de 40% mais lenta em poder bruto que a da Intel. Para evitar que o SEV parecesse injustamente ruim, os autores aplicaram uma normalização matemática nos gráficos. Isso isolou a lentidão da CPU, permitindo analisar **exclusivamente o *overhead*** (penalidade de tempo) imposto pela criptografia do TEE.
*   **Cenários, Métricas e Ferramentas:** Avaliaram-se três classes de aplicações medindo Taxa de Transferência (*Throughput*), Latência, Tempo de Inferência e Uso de CPU:
    1.  **Intensivas em Memória:** Redis e Vault (usando as ferramentas *redis-benchmark* e *vault-benchmark*).
    2.  **Intensivas em I/O (Entrada/Saída de Rede e Disco):** Servidores NGINX e NodeJS (usando a ferramenta *wrk2*).
    3.  **Intensivas em CPU:** Algoritmos de Inteligência Artificial usando PyTorch e TensorFlow.

---

### **5. Resultados**
Os resultados comprovaram desempenhos radicalmente diferentes dependendo da carga de trabalho:

*   **Cargas de Memória (Figuras 5 e 6):** O gráfico compara *throughput* vs latência. O **Intel TDX** foi a grande estrela, entregando desempenho quase idêntico ao ambiente nativo. O **SEV** ficou apenas ~22% atrás do TDX (após normalização). As piores performances foram do SGX (Gramine e Occlum), cujos gráficos exibem linhas quase verticais de latência. **Motivo:** O limite rígido do espaço EPC obriga o SGX a fazer *swapping* (paginar e encriptar) constantemente blocos de memória para o SO, criando um gargalo absurdo.
*   **Cargas de I/O e Rede (Figuras 9 e 10):** As arquiteturas de VM dominaram. O TDX manteve altíssima taxa de transferência com baixa latência, seguido de perto pelo SEV. O SGX foi catastrófico: no teste do NodeJS, o Gramine e o Occlum chegaram a travar após poucas requisições. **Motivo:** Como o SO não é confiável no SGX, toda vez que a aplicação precisa enviar/receber um pacote de rede via chamada de sistema (*Syscall*), o hardware exige um "Enclave Exit" (*Context Switching*), saindo do ambiente seguro e voltando. Esse processo é excessivamente custoso.
*   **Cargas de CPU e IA (Figuras 7 e 8):** Nesses gráficos (tempo de inferência em milissegundos), a surpresa: o **Gramine-SGX** esmagou as soluções em VM em diversos algoritmos de PyTorch, igualando-se ou até superando o TDX. **Motivo:** O processamento de redes neurais acontece inteiramente na CPU, sem necessidade de acessar a rede. Sem *syscalls*, o modelo restrito do enclave do SGX brilha e entrega proteção máxima sem penalizar o processador.
*   **Uso de Recursos (Figura 11) e Custos (Figura 12):** O TDX mostrou-se altamente otimizado, usando níveis de CPU próximos ao ambiente sem segurança. O SGX consome vastos ciclos de CPU apenas para gerenciar segurança. Ao traduzir o uso de CPU para a fatura de um provedor de nuvem (Azure), observou-se que o **SGX é a tecnologia comercial mais cara**, exigindo a contratação de servidores maiores para a mesma tarefa. O **SEV é a opção de custo mais baixo**, e o TDX assume uma posição intermediária favorável.

---

### **6. Discussão (Comparações e Limitações)**
A seção de discussão elabora sobre os *trade-offs* (compromissos) descobertos:

*   **Intel SGX vs. VM-based (TDX/SEV):** O SGX é limitado para aplicações em nuvem devido à dependência do EPC e ao pesadelo de performance gerado por interações de rede. No entanto, é insuperável no quesito isolamento se o foco for tarefas puramente matemáticas.
*   **Gramine vs. Occlum:** O veredito para rodar código no SGX é o **Gramine**. Ele supera largamente o Occlum em tempo de execução e economia de CPU porque o Occlum impõe regras isolacionistas muito pesadas (SFI), que causam degradação sem oferecer benefícios proporcionais para a maioria dos usuários.
*   **TDX vs. SEV:** O recém-lançado Intel TDX demonstrou ser uma engenharia refinada. Mesmo subtraindo matematicamente as desvantagens da CPU AMD, a arquitetura do TDX gasta menos recursos e manipula requisições de I/O de maneira mais elegante e rápida do que o AMD SEV.

---

### **7. Conclusões e Implicações Práticas**
Os autores concluem que a **Computação Confidencial atingiu a maturidade** para ser usada em larga escala e em produção sem penalizar drasticamente a estabilidade dos sistemas.

**Recomendações Práticas Destacadas:**
1.  **Para microsserviços, servidores web e bancos de dados:** Soluções baseadas em VM (**TDX e SEV**) são muito superiores em praticidade e desempenho bruto.
2.  O **Intel TDX** validou sua estreia demonstrando ser incrivelmente estável para implantação sem alterações de código (*lift-and-shift*).
3.  O **Intel SGX** (baseado em processos) não deve ser visto como obsoleto, mas como uma ferramenta de nicho: é o "padrão ouro" para proteger segredos de nível máximo, modelos sigilosos de IA ou processamento de supercomputadores (HPC), onde conexões de rede constantes não são o foco.
