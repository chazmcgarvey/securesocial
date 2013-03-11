/**
 * Copyright 2012 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package securesocial.core.providers

import securesocial.core._
import play.api.libs.oauth.{RequestToken, OAuthCalculator}
import play.api.libs.ws.WS
import play.api.{Application, Logger}
import scala.concurrent.duration._
import scala.concurrent._
import ExecutionContext.Implicits.global


/**
 * A Yahoo Provider
 */
class YahooProvider(application: Application) extends OAuth1Provider(application) {
  override def id = YahooProvider.Yahoo

  override def fillProfile(user: SocialUser): SocialUser = {
    val oauthInfo = user.oAuth1Info.get
    val call = WS.url(YahooProvider.VerifyCredentials).sign(
      OAuthCalculator(SecureSocial.serviceInfoFor(user).get.key,
      RequestToken(oauthInfo.token, oauthInfo.secret))
    ).get()

    try {
      val response = Await.result(call, 10.seconds)
      val me = (response.json \ "query" \ "results" \ "profile")
      val userId = (me \ "guid").as[String]
      val name = (me \ "nickname").as[String]
      val email = (me \ "emails" \ "handle").asOpt[String]
      val profileImage = (me \ "image" \ "imageUrl").asOpt[String]
      user.copy(
        id = UserId(userId, id),
        fullName = name,
        email = email,
        avatarUrl = profileImage
      )
    } catch {
      case e: TimeoutException => {
        Logger.error("[securesocial] timed out waiting for Yahoo")
        throw new AuthenticationException()
      }
    }
  }
}

object YahooProvider {
  val VerifyCredentials = "http://query.yahooapis.com/v1/yql?format=json&q=select%20*%20from%20social.profile%20where%20guid%3Dme%3B"
  val Yahoo = "yahoo"
}
