import Foundation
import GermConvenience

//this is growing to the point where it should get broken down into subdomains
enum OAuthError: Error {
	case missingScheme
	case missingHTTPMethod
	case missingUrl
	case missingDPoPKey
	case missingIssuer
	case insecureScheme
	case unrecognizedTokenType
	case redirectMissingComponents
	case missingAuthCode
	case invalidRequest
	case invalidResponse
	case redirectError(String, String?)
	case stateTokenMismatch(String, String)
	case issuingServerMismatch(String, String)
	case accessDenied
	case invalidScope
	case httpResponse(response: HTTPURLResponse)
	case oauthError(OAuthErrorResponse, Int)
	case notImplemented
}

extension OAuthError: LocalizedError {
	var errorDescription: String? {
		switch self {
		case .missingScheme: "Missing scheme"
		case .missingHTTPMethod: "Missing HTTP method"
		case .missingUrl: "Missing URL"
		case .missingDPoPKey: "Missing dPoP key"
		case .missingIssuer:
			"Missing iss parameter when authorization server supports issuer identification"
		case .insecureScheme: "Insecure scheme"
		case .unrecognizedTokenType: "Unrecognized Token Type"
		case .redirectMissingComponents: "Redirect missing components"
		case .missingAuthCode: "Missing authorization code"
		case .invalidRequest: "Invalid request"
		case .invalidResponse: "Invalid response"
		case .stateTokenMismatch(
			let expected,
			let got
		): "State token did not match, expected \(expected), got \(got)"
		case .issuingServerMismatch(let expected, let got):
			"Issuing server did not match, expected \(expected), got \(got)"
		case .redirectError(let error, let errorDescription):
			if let description = errorDescription {
				"Redirect error: \(error) \(description)"
			} else {
				"Redirect error: \(error)"
			}
		case .accessDenied:
			"The resource owner or authorization server denied the request."
		case .invalidScope:
			"The requested scope is invalid, unknown, or malformed."
		case .httpResponse(let response):
			"HTTP error with status code: \(response.statusCode), response: \(response)"
		case .oauthError(let errorBody, let statusCode):
			"OAuth error with status code: \(statusCode),  body: \(errorBody)"
		case .notImplemented: "Not implemented"
		}
	}
}

//Abstraction of ASWebAuthentication or AuthTabIntent
public typealias UserAuthenticator = @Sendable (URL, String) async throws -> URL
