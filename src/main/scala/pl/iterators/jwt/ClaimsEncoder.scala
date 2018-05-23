package pl.iterators.jwt

import com.auth0.jwt.JWTCreator.Builder

trait ClaimsEncoder[T] {
  def encode(builder: Builder)(claims: T): Builder
}
