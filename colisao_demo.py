#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
colisao_demo.py
===============
Ilustra COMO se fabrica uma colisao de MD5 e, principalmente, os DOIS NIVEIS do
ataque do Flame -- desfazendo a confusao comum de que "o malware estaria dentro
do arquivo que colide".

  PARTE 1: por que forca bruta NAO cola dois arquivos quaisquer.
  NIVEL 1: a colisao forja um CERTIFICADO confiavel (nao contem o malware).
  NIVEL 2: com o certificado forjado, o atacante assina o CODIGO -- um arquivo
           SEPARADO -- e o Windows confia na cadeia inteira.

Reaproveita o RSA didatico de flame_demo.py. Sem dependencias externas.
Uso: python3 colisao_demo.py

Trabalho de Seguranca de Sistemas -- Escola Politecnica / PUCRS
"""

import hashlib
import re
from flame_demo import gera_par_de_chaves, assinar, verificar


def titulo(txt):
    print("\n" + "=" * 70)
    print("  " + txt)
    print("=" * 70)


def md5(dados):
    return hashlib.md5(dados).hexdigest()


# ============================================================================
#  PARTE 1 -- Por que forca bruta NAO cola dois arquivos quaisquer
# ============================================================================

def acha_colisao_parcial(nbits):
    """Ataque do aniversario 'de brinquedo': duas entradas com o mesmo inicio de MD5."""
    vistos = {}
    i = 0
    while True:
        x = i.to_bytes(8, "big")
        h = int.from_bytes(hashlib.md5(x).digest(), "big") >> (128 - nbits)
        if h in vistos:
            return i + 1, vistos[h], x
        vistos[h] = x
        i += 1


def parte1():
    titulo("PARTE 1 -- Forca bruta NAO cola dois arquivos quaisquer")
    print("Bater um hash de 128 bits ja existente exigiria ~2**128 tentativas.")
    print("Vamos SENTIR isso colidindo so os PRIMEIROS bits do MD5:\n")
    print("  bits alvo | tentativas ate colidir | esperado (~2**(bits/2))")
    print("  ----------+------------------------+------------------------")
    for nbits in (8, 16, 24, 32, 40):
        tentativas, _, _ = acha_colisao_parcial(nbits)
        print("  %8d  | %20s   | ~%s" % (nbits, f"{tentativas:,}", f"{2**(nbits//2):,}"))
    print("\n  O esforco DOBRA a cada ~2 bits. Para 128 bits daria ~2**64 tentativas")
    print("  (~585 anos a 1 bilhao/s). O MD5 nao caiu por forca bruta, e sim pela")
    print("  matematica (Wang et al., 2004), que acha uma colisao real em segundos.")


# ============================================================================
#  Modelo de certificado + a colisao real de Wang (dois cabecalhos, mesmo MD5)
# ============================================================================

CABECALHO_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
CABECALHO_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)


def monta_corpo(chave_publica_atacante):
    """
    O 'corpo' do certificado -- IDENTICO nos dois arquivos. Contem a CHAVE PUBLICA
    do atacante e a regra do 'interruptor': o cabecalho decide o campo 'uso'.
    (Simplificacao honesta: com a colisao facil que reproduzimos aqui, os dois
     certificados so podem diferir no cabecalho; o Flame real usou 'chosen-prefix'
     para fazer os campos diferirem de verdade. O principio e o mesmo.)
    """
    e, n = chave_publica_atacante
    return (b"|titular=Servico de Licenciamento"
            b"|chave_publica_e=" + str(e).encode() +
            b"|chave_publica_n=" + str(n).encode() +
            b"|regra: cabecalho A => uso=LICENCA ; cabecalho B => uso=ASSINATURA_DE_CODIGO|")


def chave_do_cert(cert):
    """O que o Windows le de dentro do certificado: a chave publica do titular."""
    corpo = cert[128:]
    e = int(re.search(rb"chave_publica_e=(\d+)", corpo).group(1))
    n = int(re.search(rb"chave_publica_n=(\d+)", corpo).group(1))
    return (e, n)


def uso_do_cert(cert):
    """O 'para que serve' o certificado -- selecionado pelo cabecalho que colide."""
    if cert[:128] == CABECALHO_A:
        return "LICENCA"
    if cert[:128] == CABECALHO_B:
        return "ASSINATURA_DE_CODIGO"
    return "DESCONHECIDO"


# ============================================================================
#  NIVEL 1 -- A colisao forja um certificado confiavel
# ============================================================================

def nivel1(microsoft_pub, microsoft_priv, atacante_pub):
    titulo("NIVEL 1 -- A colisao forja um CERTIFICADO (nao o malware)")
    print("Um certificado diz 'esta chave publica pertence a X e serve para Y', e e")
    print("assinado por uma autoridade em que o Windows confia. O que se assina e o")
    print("HASH do certificado.\n")

    corpo = monta_corpo(atacante_pub)
    cert_isca = CABECALHO_A + corpo    # o que a Microsoft vai assinar (uso=LICENCA)
    cert_codigo = CABECALHO_B + corpo  # o gemeo do atacante (uso=ASSINATURA_DE_CODIGO)

    print("  O atacante fabrica DOIS certificados com o MESMO MD5:")
    print("    cert_isca   : uso=%s  (parece inofensivo)" % uso_do_cert(cert_isca))
    print("    cert_codigo : uso=%s  (contem a chave publica do atacante)" % uso_do_cert(cert_codigo))
    print("    MD5(cert_isca)   = %s" % md5(cert_isca))
    print("    MD5(cert_codigo) = %s" % md5(cert_codigo))
    print("    mesmo MD5? %s\n" % (md5(cert_isca) == md5(cert_codigo)))

    print("  A Microsoft assina o cert_isca (o hash dele, com MD5)...")
    assinatura_ms = assinar(cert_isca, microsoft_priv, "md5")
    print("  ...e por a colisao, essa assinatura tambem vale para o cert_codigo:")
    forjado = verificar(cert_codigo, assinatura_ms, microsoft_pub, "md5")
    print("    Assinatura da Microsoft e valida no cert_codigo? %s" %
          ("SIM  [!!] certificado de codigo FORJADO" if forjado else "nao"))
    print("\n  Repare: o cert_codigo NAO contem virus. Ele e perigoso porque agora e")
    print("  uma credencial de assinatura de codigo, confiavel, cuja chave privada")
    print("  o atacante possui.")
    return cert_codigo, assinatura_ms


# ============================================================================
#  NIVEL 2 -- Com o certificado, o atacante assina o CODIGO (arquivo separado)
# ============================================================================

def nivel2(cert_codigo, assinatura_cert, microsoft_pub, atacante_priv):
    titulo("NIVEL 2 -- O atacante assina o CODIGO (um arquivo a parte)")
    malware = b"FLAME.SYS -- grava o microfone, captura tela e teclado, exfiltra dados"
    print("  O malware e um arquivo SEPARADO, assinado normalmente (sem colisao),")
    print("  com a chave PRIVADA do certificado forjado:\n")
    print("    codigo    = %r" % malware)
    assinatura_codigo = assinar(malware, atacante_priv, "sha256")
    print("    -> assinatura do codigo gerada (SHA-256, comum).\n")

    print("  Agora o Windows recebe [ codigo + assinatura + cert_codigo ] e verifica:")
    chave_cert = chave_do_cert(cert_codigo)
    ok_codigo = verificar(malware, assinatura_codigo, chave_cert, "sha256")
    ok_cadeia = verificar(cert_codigo, assinatura_cert, microsoft_pub, "md5")
    ok_uso = uso_do_cert(cert_codigo) == "ASSINATURA_DE_CODIGO"
    print("    1) o codigo bate com a chave publica DENTRO do certificado? .. %s" % ("SIM" if ok_codigo else "nao"))
    print("    2) o certificado esta assinado pela Microsoft (cadeia)? ...... %s" % ("SIM" if ok_cadeia else "nao"))
    print("    3) o certificado autoriza assinar codigo? .................... %s" % ("SIM" if ok_uso else "nao"))
    print("\n  Windows: %s" %
          ("[!!] CONFIA E INSTALA o malware." if (ok_codigo and ok_cadeia and ok_uso) else "rejeita."))

    # o proprio codigo nao tem colisao: adulterar 1 byte quebra a assinatura dele
    adulterado = b"X" + malware[1:]
    quebrou = not verificar(adulterado, assinatura_codigo, chave_cert, "sha256")
    print("\n  (O codigo em si NAO tem colisao: trocar 1 byte dele ja invalida a")
    print("   assinatura -> %s. A colisao foi so no Nivel 1, para obter o certificado.)"
          % ("verificacao falha" if quebrou else "?"))


def defesa(microsoft_pub, microsoft_priv, atacante_pub):
    titulo("A defesa -- SHA-256 quebra o NIVEL 1")
    corpo = monta_corpo(atacante_pub)
    cert_isca = CABECALHO_A + corpo
    cert_codigo = CABECALHO_B + corpo
    print("  Se a autoridade assinar o certificado com SHA-256:")
    print("    SHA-256(cert_isca)   = %s..." % hashlib.sha256(cert_isca).hexdigest()[:24])
    print("    SHA-256(cert_codigo) = %s..." % hashlib.sha256(cert_codigo).hexdigest()[:24])
    assinatura_ms = assinar(cert_isca, microsoft_priv, "sha256")
    forjado = verificar(cert_codigo, assinatura_ms, microsoft_pub, "sha256")
    print("    Assinatura do cert_isca vale para o cert_codigo? %s" %
          ("valida" if forjado else "NAO -- ataque bloqueado no Nivel 1"))
    print("\n  Sem o Nivel 1, o atacante nunca obtem um certificado confiavel, e o")
    print("  Nivel 2 nem chega a acontecer. Por isso o mundo aposentou o MD5.")


def main():
    print("""
+--------------------------------------------------------------------+
|   FABRICANDO COLISOES E OS DOIS NIVEIS DO ATAQUE FLAME              |
|   Seguranca de Sistemas / PUCRS                                     |
+--------------------------------------------------------------------+""")
    parte1()
    print("\n  (gerando chaves RSA da 'Microsoft' e do atacante...)")
    microsoft_pub, microsoft_priv = gera_par_de_chaves(1024)
    atacante_pub, atacante_priv = gera_par_de_chaves(1024)
    cert_codigo, assinatura_cert = nivel1(microsoft_pub, microsoft_priv, atacante_pub)
    nivel2(cert_codigo, assinatura_cert, microsoft_pub, atacante_priv)
    defesa(microsoft_pub, microsoft_priv, atacante_pub)
    print()


if __name__ == "__main__":
    main()
