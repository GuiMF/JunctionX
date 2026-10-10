# Cloud posture — entrega de Santiago

C1–C5 implementados para os ficheiros fornecidos. Python 3.9+, biblioteca padrão,
sem serviços externos. Executar os comandos na raiz do repositório.

| Tarefa | Entrega | Verificação |
| --- | --- | --- |
| C1 | Leitura dos três exports; configuração, ARNs, datas, tags e evidência | 10 chaves, 6 load balancers, 5 certificados e 7 listeners |
| C2 | Relações explícitas por ARN; responsáveis KMS | 5 certificados resolvidos; referências em falta produzem erros |
| C3 | Algoritmos/utilizações separados; políticas por tipo de load balancer | Protocolos e conjuntos de cifras conferidos nas tabelas oficiais AWS em 2026-10-10 |
| C4 | Indicadores operacionais separados da avaliação de risco | Expiração, SHA-1, rotação, eliminação, TLS antigo e ações HTTP; data de avaliação explícita |
| C5 | Fixture modificada e comparação executável | Um listener passa a suportar troca de chaves híbrida; certificado e IDs mantidos |

## Executar

```sh
python3 -B -m unittest discover -s tests -v
python3 -B -m adapters.cloud cloud-posture --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud.json
python3 -B -m adapters.cloud tests/fixtures/cloud-modified --evaluated-at 2026-10-10T12:00:00Z > /tmp/quantumtrace-cloud-modified.json
python3 -B -m adapters.cloud_demo > /tmp/quantumtrace-cloud-demo.json
```

O módulo principal também pode ser importado com `from adapters.cloud import
scan_cloud`. O contrato de saída está descrito no README da raiz.

## Resultados esperados

Com avaliação em `2026-10-10T12:00:00Z`, ambos os inputs produzem 28 recursos
(21 principais e 7 filhos), 25 observações e 5 relações `uses_certificate`
resolvidas, sem erros. As cinco políticas originais estão mapeadas; o algoritmo
negociado dos cinco listeners TLS continua desconhecido.

Os indicadores operacionais originais são:

- 2 chaves com rotação desativada; `NOT_APPLICABLE` não é desativação.
- 1 chave em `PendingDeletion`; a data de eliminação é preservada como configuração.
- 1 certificado expirado e com assinatura SHA-1.
- 2 listeners com TLS 1.0 ou 1.1 permitido.
- 1 listener HTTP com encaminhamento. O outro listener HTTP redireciona para HTTPS.

São condições dos snapshots sintéticos de setembro, avaliadas na data indicada.
Não são verificações de uma conta AWS atual. A idade de cada snapshot aparece
em `snapshots[].age_seconds`; valores negativos indicam avaliação anterior ao export.

## Demonstração curta

1. Abrir `changes[0]` no resultado de `adapters.cloud_demo`.
2. Mostrar `partner-api-alb`, com política original
   `ELBSecurityPolicy-TLS13-1-2-2021-06`: TLS 1.2/1.3, sem capacidade híbrida PQ.
3. Mostrar a cópia modificada com
   `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`: capacidade híbrida PQ e grupos suportados.
4. Abrir a evidência e a relação `examples.relationships[0]` para o certificado.
5. Explicar: "Alterámos um ficheiro de demonstração. A política permite troca de
   chaves híbrida se o cliente suportar ML-KEM; continua a aceitar ligações clássicas.
   O certificado ECDSA não mudou e não observámos uma negociação de rede."

O novo conjunto de cifras é mais restritivo; validar os clientes reais antes de
recomendar uma migração de produção. A AWS documenta os requisitos e o fallback em
[políticas ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html).
As [políticas NLB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html)
são consultadas separadamente.

A comparação rejeita alterações adicionais à configuração de qualquer recurso,
incluindo chaves, certificados e portas. Assim, só atribui o resultado à mudança
da política TLS indicada.

## Entrega aos responsáveis 04 e 05

### Renovação do certificado importado

Executar `python3 -B -m adapters.cloud_demo --certificate-renewal`. O exemplo
gerado está em [cloud-renewal-demo.json](cloud-renewal-demo.json).

A fixture separada `tests/fixtures/cloud-renewed/` simula reimportação do
certificado de `legacy-tcp.internal.example.com`: novas datas de validade e
importação, assinatura SHA-256, mesmo ARN, domínio e chave RSA-2048. O timestamp
do export de certificados é atualizado; os exports KMS e load balancers não mudam.
À data fixa da demo, desaparecem apenas os indicadores de expiração e SHA-1
desse certificado. TLS antigo e restantes problemas continuam visíveis no scan.

Certificados importados não têm renovação automática ACM: é necessário obter
um certificado novo junto do emissor e reimportá-lo. A reimportação conserva o
ARN e as associações; exige o mesmo tipo e tamanho de chave.
Fontes: [renovação manual](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html)
e [restrições de reimportação](https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html).

Esta é uma simulação de metadados, sem emissão de certificados, chaves privadas
ou alteração de AWS. Corrige postura clássica na fixture; RSA permanece clássico.
O comparador rejeita outras alterações e certificados inválidos na data de avaliação.

### Exemplos de integração

[cloud-demo.json](cloud-demo.json) contém exemplos gerados pelo código:
chave RSA de `billing`, chave AES de `platform`, listener e certificado ligados,
observações com evidência, comparação e cobertura. Os caminhos da evidência são
relativos à raiz do repositório e os ficheiros de origem permanecem disponíveis.

A avaliação central, recomendações, pontuação, API e CycloneDX pertencem ao módulo
04. O adapter devolve `assessment_status: pending_core`, mantendo as classificações
desconhecidas até essa avaliação. As propriedades `tls_policy` descrevem capacidades
configuradas; `negotiated_group` e `observed_at` permanecem null.

O contrato implementado usa o exemplo do plano; ainda precisa de ser alinhado com
o contrato definitivo do responsável 04. O frontend pode usar estes exemplos para
inventário, detalhe da evidência e comparação enquanto essa integração acontece.
O ficheiro HTML do quadro de tarefas guarda progresso no browser e não sincroniza
com os checkboxes do plano Markdown.
O snapshot [cloud-progress.json](cloud-progress.json) permite importar a conclusão
de C1–C5 no quadro. A importação substitui o progresso local: exportar primeiro o
estado da equipa se já tiver outras tarefas ou responsáveis preenchidos.
