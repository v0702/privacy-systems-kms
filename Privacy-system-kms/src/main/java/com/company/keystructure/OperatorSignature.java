package com.company.keystructure;

/**
 * <p>
 * The signature of a trust by an operator
 * </p>
 * @param generalSignature the signature by an operator of a trust, GeneralSignature
 * @param idOfTrust the id of the Trust that is signed by the operator, of type int
 */
public record OperatorSignature(GeneralSignature generalSignature, int idOfTrust) {

}
