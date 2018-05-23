package pl.iterators.jwt

import com.auth0.jwt.JWTCreator.Builder
import shapeless.Witness
import shapeless.labelled.FieldType

trait ClaimsEncoder[T] {
  def encode(builder: Builder)(claims: T): Builder
}

object ClaimsEncoder {
  private class FieldTypeEncoder[K, V](name: String, thisType: PrivateClaimType[V])
    extends ClaimsEncoder[FieldType[K, V]] {
    override def encode(builder: Builder)(claims: FieldType[K, V]) =
      thisType.encode(builder)(name, claims)
  }
  implicit def StringFieldTypeEncoder[K <: String, V](
                                                       implicit witness: Witness.Aux[K],
                                                       thisType: PrivateClaimType[V]): ClaimsEncoder[FieldType[K, V]] =
    new FieldTypeEncoder[K, V](witness.value, thisType)
  implicit def SymbolFieldTypeEncoder[K <: Symbol, V](
                                                       implicit witness: Witness.Aux[K],
                                                       thisType: PrivateClaimType[V]): ClaimsEncoder[FieldType[K, V]] =
    new FieldTypeEncoder[K, V](witness.value.name, thisType)
}
