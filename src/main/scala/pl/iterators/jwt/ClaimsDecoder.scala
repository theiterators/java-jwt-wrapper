package pl.iterators.jwt

import java.util.{Map => jMap}

import com.auth0.jwt.interfaces.Claim
import shapeless.labelled._
import shapeless.{::, HList, HNil, Witness}

trait ClaimsDecoder[T] {
  def decode(claims: jMap[String, Claim]): T
}

object ClaimsDecoder {
  private class FieldTypeDecoder[K, V](name: String,
                                       fieldBuilder: FieldBuilder[K],
                                       thisType: PrivateClaimType[V])
    extends ClaimsDecoder[FieldType[K, V]] {
    def decode(claims: jMap[String, Claim]) = fieldBuilder(thisType.decode(claims)(name))
  }
  implicit def StringFieldTypeDecoder[K <: String, V](
                                                       implicit witness: Witness.Aux[K],
                                                       thisType: PrivateClaimType[V]): ClaimsDecoder[FieldType[K, V]] =
    new FieldTypeDecoder[K, V](witness.value, field[K], thisType)
  implicit def SymbolFieldTypeEncoder[K <: Symbol, V](
                                                       implicit witness: Witness.Aux[K],
                                                       thisType: PrivateClaimType[V]): ClaimsDecoder[FieldType[K, V]] =
    new FieldTypeDecoder[K, V](witness.value.name, field[K], thisType)

  implicit object HNilDecoder extends ClaimsDecoder[HNil] {
    def decode(claims: jMap[String, Claim]) = HNil
  }
  implicit def HListDecoder[K, V, Rest <: HList](
                                                  implicit headDecoder: ClaimsDecoder[FieldType[K, V]],
                                                  restDecoder: ClaimsDecoder[Rest]): ClaimsDecoder[FieldType[K, V] :: Rest] =
    (claims: jMap[String, Claim]) => {
      val head = headDecoder.decode(claims)
      val rest = restDecoder.decode(claims)

      ::(head, rest)
    }
}
