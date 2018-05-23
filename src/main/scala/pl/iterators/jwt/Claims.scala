package pl.iterators.jwt

import shapeless.{HList, LabelledGeneric}

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
}

trait Claims[Of] {
  type Repr

  def privateClaims(of: Of): Repr
  def encoder: ClaimsEncoder[Repr]

  def of(claims: Repr): Of
  def decoder: ClaimsDecoder[Repr]
}
