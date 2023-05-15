package com.company.keystructure;

import java.io.Serializable;

/**
 * <p>
 * This structure stores the trustContent and domainKeys
 * without a signature
 * </p>
 * <pre>
 * |--------------------|
 * |   DomainContent    |
 * |-------|------------|
 * | Trust | DomainKeys |
 * |-------|------------|
 *
 * |------------------------------------------------------------------|
 * |                              Trust                               |
 * |----------------------------------------------|-------------------|
 * |                 TrustContent                 |  GeneralSignature |
 * |----------------------------------------------|-------------------|
 * |Identifier|PK1|...|PKn|Quorum|Predecessor Hash|signature|PublicKey|
 * |----------------------------------------------|-------------------|
 *
 * |--------------------------------------------------------|
 * |                       DomainKeys                       |
 * |------------|------------|-----|------------|-----------|
 * | Enc(Pk1,K) | Enc(Pk2,K) | ... | Enc(Pki,K) | Enc(K,MK) |
 * |------------|------------|-----|------------|-----------|
 * </pre>
 * @param trust the trust as Trust, to store
 * @param domainKeys the domainKeys as DomainKeys, to store
 */
public record DomainContent(Trust trust, DomainKeys domainKeys) implements Serializable {

}