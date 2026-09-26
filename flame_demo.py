#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flame_demo.py
=============
Demonstracao pratica do ataque do malware Flame (2012): como uma COLISAO de MD5
permite FORJAR uma assinatura digital, e por que o SHA-256 fecha essa porta.

Ideia central: uma assinatura digital NAO assina o arquivo -- assina o HASH do
arquivo. Logo, se dois arquivos diferentes tem o MESMO hash, uma unica assinatura
vale para os dois. O Flame explorou exatamente isso para se passar pela Microsoft.

Este script nao depende de nenhuma biblioteca externa: implementamos um RSA
"didatico" (RSA texto-livro) e usamos o modulo padrao hashlib para os hashes.
                       -------------------------------------------------
NOTA: o RSA aqui e simplificado (sem preenchimento/padding) porque o objetivo e
deixar visivel que "assina-se o hash". Assinaturas reais usam padding (PKCS#1,
PSS); isso nao muda em nada a licao sobre colisao de hash demonstrada aqui.

Trabalho de Seguranca de Sistemas -- Escola Politecnica / PUCRS
Uso: python3 flame_demo.py
"""

import hashlib
import random


# ============================================================================
#  1. RSA didatico (geracao de chaves, assinatura e verificacao)
# ============================================================================

def eh_primo_provavel(n, k=40):
    """Teste de primalidade de Miller-Rabin."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gera_primo(bits):
    """Sorteia um primo com o numero de bits pedido."""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if eh_primo_provavel(n):
            return n


def gera_par_de_chaves(bits=1024):
    """Gera (chave_publica, chave_privada) do RSA. Retorna ((e,n), (d,n))."""
    e = 65537
    while True:
        p = gera_primo(bits // 2)
        q = gera_primo(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)          # inverso modular (Python 3.8+)
        return (e, n), (d, n)


def hash_como_inteiro(dados, algoritmo):
    """Calcula o hash dos 'dados' e devolve como numero inteiro."""
    digest = hashlib.new(algoritmo, dados).hexdigest()
    return int(digest, 16)


def assinar(dados, chave_privada, algoritmo):
    """Assinatura = cifrar (com a chave privada) o HASH da mensagem."""
    d, n = chave_privada
    return pow(hash_como_inteiro(dados, algoritmo) % n, d, n)


def verificar(dados, assinatura, chave_publica, algoritmo):
    """Verifica: decifra a assinatura (chave publica) e compara com o hash do arquivo."""
    e, n = chave_publica
    return pow(assinatura, e, n) == (hash_como_inteiro(dados, algoritmo) % n)


# ============================================================================
#  2. A colisao real de MD5 (par classico de Wang et al., 2004)
#     Dois arquivos DIFERENTES de 128 bytes com o MESMO MD5.
# ============================================================================

ARQUIVO_A = bytes.fromhex(   # "o certificado benigno" -- o que a Microsoft assinaria
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)

ARQUIVO_B = bytes.fromhex(   # "o certificado malicioso" -- carrega o codigo do atacante
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)


# ============================================================================
#  3. Utilidades de apresentacao (deixa a saida no terminal legivel)
# ============================================================================

def titulo(txt):
    print("\n" + "=" * 70)
    print("  " + txt)
    print("=" * 70)


def h(dados, algoritmo):
    return hashlib.new(algoritmo, dados).hexdigest()


def resumo_hex(dados, n=16):
    return dados[:n].hex(" ")


def bytes_diferentes(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


# ============================================================================
#  4. A demonstracao
# ============================================================================

def main():
    print("""
+--------------------------------------------------------------------+
|   A COLISAO DO FLAME  ---  assinatura digital, MD5 e SHA-256        |
|   Seguranca de Sistemas / PUCRS                                     |
+--------------------------------------------------------------------+

Ideia central: a assinatura digital assina o HASH do arquivo, nao o
arquivo. Se dois arquivos tem o mesmo hash, uma assinatura vale para os
dois. Foi assim que o Flame se passou pela Microsoft.""")

    # A "Microsoft" gera seu par de chaves.
    titulo("Setup: a 'Microsoft' gera seu par de chaves RSA")
    chave_publica, chave_privada = gera_par_de_chaves(1024)
    print("  Chave publica (e, n)  -> usada por todos para VERIFICAR")
    print("  Chave privada (d, n)  -> secreta, usada para ASSINAR")
    print("  Modulo n tem %d bits." % chave_publica[1].bit_length())

    # ------------------------------------------------------------------ ATO 1
    titulo("ATO 1 -- Como a assinatura digital funciona (caso honesto)")
    print("A Microsoft assina o Arquivo A usando SHA-256:")
    print("  SHA-256(A) = %s" % h(ARQUIVO_A, "sha256"))
    assinatura = assinar(ARQUIVO_A, chave_privada, "sha256")
    print("  -> assinatura gerada.\n")

    ok = verificar(ARQUIVO_A, assinatura, chave_publica, "sha256")
    print("  Verificando o proprio Arquivo A ............ %s" % ("VALIDA  [OK]" if ok else "invalida"))

    # Adultera 1 byte de A e mostra que a verificacao quebra (efeito avalanche).
    adulterado = bytearray(ARQUIVO_A)
    adulterado[0] ^= 0x01
    adulterado = bytes(adulterado)
    ok2 = verificar(adulterado, assinatura, chave_publica, "sha256")
    print("  Verificando A com 1 byte trocado ........... %s" % ("valida" if ok2 else "INVALIDA  [OK]"))
    print("\n  Conclusao: mexeu no arquivo, o hash muda, a assinatura nao bate.")
    print("  E assim que a assinatura deveria proteger a integridade.")

    # ------------------------------------------------------------------ ATO 2
    titulo("ATO 2 -- O ataque do Flame: colisao de MD5")
    print("O atacante tem DOIS arquivos diferentes:")
    print("  Arquivo A (benigno)  : %s ..." % resumo_hex(ARQUIVO_A))
    print("  Arquivo B (malicioso): %s ..." % resumo_hex(ARQUIVO_B))
    print("  Sao %d bytes cada e diferem em %d bytes." %
          (len(ARQUIVO_A), bytes_diferentes(ARQUIVO_A, ARQUIVO_B)))
    print()
    print("  MD5(A) = %s" % h(ARQUIVO_A, "md5"))
    print("  MD5(B) = %s" % h(ARQUIVO_B, "md5"))
    colide = h(ARQUIVO_A, "md5") == h(ARQUIVO_B, "md5")
    print("  -> MD5 identico? %s" % ("SIM  <-- colisao!" if colide else "nao"))
    print()
    print("O golpe: a Microsoft assina o Arquivo A (benigno) usando MD5...")
    assinatura_md5 = assinar(ARQUIVO_A, chave_privada, "md5")
    print("  -> assinatura de A gerada (com MD5).\n")
    print("...e o atacante entrega o Arquivo B (malicioso) com ESSA mesma assinatura:")
    forjado = verificar(ARQUIVO_B, assinatura_md5, chave_publica, "md5")
    print("  Windows verifica o Arquivo B .............. %s" %
          ("VALIDA  [!!] MALWARE ACEITO COMO MICROSOFT" if forjado else "invalida"))
    print("\n  A assinatura feita para A validou B, sem o atacante tocar na")
    print("  chave privada. A confianca foi FORJADA. Foi assim que o Flame")
    print("  fez o Windows Update instalar o malware sozinho.")

    # ------------------------------------------------------------------ ATO 3
    titulo("ATO 3 -- A defesa: trocar MD5 por SHA-256")
    print("Os MESMOS dois arquivos, agora sob SHA-256:")
    print("  SHA-256(A) = %s" % h(ARQUIVO_A, "sha256"))
    print("  SHA-256(B) = %s" % h(ARQUIVO_B, "sha256"))
    colide256 = h(ARQUIVO_A, "sha256") == h(ARQUIVO_B, "sha256")
    print("  -> SHA-256 identico? %s" % ("sim" if colide256 else "NAO  <-- hashes diferentes"))
    print()
    print("A Microsoft assina o Arquivo A usando SHA-256...")
    assinatura_sha = assinar(ARQUIVO_A, chave_privada, "sha256")
    print("...e o atacante tenta reaproveitar a assinatura no Arquivo B:")
    bloqueado = verificar(ARQUIVO_B, assinatura_sha, chave_publica, "sha256")
    print("  Windows verifica o Arquivo B .............. %s" %
          ("valida" if bloqueado else "INVALIDA  [OK] ATAQUE BLOQUEADO"))
    print("\n  Sem colisao, a assinatura de A nao transfere para B.")
    print("  Por isso o mundo aposentou o MD5 e usa SHA-256.")

    # ------------------------------------------------------------------ FECHO
    titulo("Resumo")
    print("  Assinatura digital = assinar o HASH do arquivo.")
    print("  A seguranca depende de o hash ser resistente a colisao.")
    print("  MD5 nao era -> o Flame forjou a assinatura da Microsoft.")
    print("  SHA-256 e -> o mesmo ataque falha.\n")


if __name__ == "__main__":
    main()
