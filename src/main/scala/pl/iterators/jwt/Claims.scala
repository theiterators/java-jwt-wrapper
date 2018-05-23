package pl.iterators.jwt

trait Claims[Of] {
  type Repr

  def privateClaims(of: Of): Repr
  def encoder: ClaimsEncoder[Repr]

  def of(claims: Repr): Of
  def decoder: ClaimsDecoder[Repr]
}
