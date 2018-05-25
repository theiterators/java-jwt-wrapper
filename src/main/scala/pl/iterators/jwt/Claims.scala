package pl.iterators.jwt

import com.auth0.jwt.JWTCreator
import com.auth0.jwt.exceptions.InvalidClaimException
import com.auth0.jwt.interfaces.Claim
import shapeless.labelled.{field, FieldType}
import shapeless.{:+:, CNil, Coproduct, HList, Inl, Inr, LabelledGeneric, Witness}

object Claims {
  def of[Record](implicit recordEncoder: ClaimsEncoder[Record],
                 recordDecoder: ClaimsDecoder[Record]): Claims[Record] = new Claims[Record] {
    override type Repr = Record

    override def privateClaims(of: Record) = of
    override def encoder                   = recordEncoder

    override def of(claims: Repr) = claims
    override def decoder          = recordDecoder
  }

  implicit def labelledGenericClaims[Gen, Repr0 <: HList](
                                                           implicit gen: LabelledGeneric.Aux[Gen, Repr0],
                                                           genEncoder: ClaimsEncoder[Repr0],
                                                           genDecoder: ClaimsDecoder[Repr0]): Claims[Gen] = new Claims[Gen] {
    override type Repr = Repr0

    override def privateClaims(of: Gen) = gen.to(of)
    override def encoder                = genEncoder

    override def of(claims: Repr) = gen.from(claims)
    override def decoder          = genDecoder
  }

  type Aux[Of, Repr0] = Claims[Of] { type Repr = Repr0 }

  implicit def genHierarchyClaims[Adt, CopK <: Coproduct](
                                                           implicit gen: LabelledGeneric.Aux[Adt, CopK],
                                                           copClaims: Claims.Aux[CopK, CopK]): Claims[Adt] =
    new Claims[Adt] {
      override type Repr = CopK

      override def privateClaims(of: Adt) = gen.to(of)
      override val encoder                = copClaims.encoder

      override def of(claims: Repr) = gen.from(claims)
      override val decoder          = copClaims.decoder
    }

  implicit object CNilClaims extends Claims[CNil] {
    override type Repr = CNil

    override def privateClaims(of: CNil) = of.impossible
    override def encoder = new ClaimsEncoder[CNil] {
      override def encode(builder: JWTCreator.Builder)(claims: CNil) = claims.impossible
    }
    override def of(claims: Repr) = claims.impossible
    override def decoder =
      (_: java.util.Map[String, Claim]) =>
        throw new InvalidClaimException(s"The Claim 'type' is missing")
  }

  implicit def coproductClaims[K <: Symbol, Repr0, Head, Tail <: Coproduct](
                                                                             implicit witness: Witness.Aux[K],
                                                                             headClaims: Claims[Head],
                                                                             tailClaims: Claims[Tail])
  : Claims.Aux[FieldType[K, Head] :+: Tail, FieldType[K, Head] :+: Tail] =
    new Claims[FieldType[K, Head] :+: Tail] {
      override type Repr = FieldType[K, Head] :+: Tail

      override def privateClaims(of: FieldType[K, Head] :+: Tail) = of
      override def encoder = new ClaimsEncoder[Repr] {
        private val hEncoder = headClaims.encoder

        override def encode(builder: JWTCreator.Builder)(claims: Repr) =
          claims.eliminate(
            h => hEncoder.encode(builder.withClaim("type", headName))(headClaims.privateClaims(h)),
            t => tailClaims.encoder.encode(builder)(tailClaims.privateClaims(t))
          )
      }

      override def of(claims: Repr) = claims
      override def decoder = (claims: java.util.Map[String, Claim]) => {
        val `type` = claims.get("type").asString()
        if (`type` == headName)
          Inl(field[K](headClaims.of(headClaims.decoder.decode(claims))))
        else
          Inr(tailClaims.of(tailClaims.decoder.decode(claims)))
      }

      private val headName = witness.value.name
    }
}

trait Claims[Of] {
  type Repr

  def privateClaims(of: Of): Repr
  def encoder: ClaimsEncoder[Repr]

  def of(claims: Repr): Of
  def decoder: ClaimsDecoder[Repr]
}
