package pl.iterators.jwt

object Claims {
  def of[Record](implicit recordEncoder: ClaimsEncoder[Record],
                 recordDecoder: ClaimsDecoder[Record]): Claims[Record] = new Claims[Record] {
    override type Repr = Record

    override def privateClaims(of: Record) = of
    override def encoder                   = recordEncoder

    override def of(claims: Repr) = claims
    override def decoder          = recordDecoder
  }
}

trait Claims[Of] {
  type Repr

  def privateClaims(of: Of): Repr
  def encoder: ClaimsEncoder[Repr]

  def of(claims: Repr): Of
  def decoder: ClaimsDecoder[Repr]
}
