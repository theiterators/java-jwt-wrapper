package pl.iterators.jwt

import java.util.{Map => jMap}

import com.auth0.jwt.interfaces.Claim

trait ClaimsDecoder[T] {
  def decode(claims: jMap[String, Claim]): T
}
