import Foundation
import GermConvenience

import struct HTTPTypes.HTTPResponse

//this is growing to the point where it should get broken down into subdomains
extension OAuth {
	public enum Errors: LocalizedError {
		case missingScheme
		case missingIssuer
		case insecureScheme
		case unrecognizedTokenType
		case missingAuthCode
		case tokenInvalid
		case invalidRequest
		case invalidResponse
		case redirectError(String, String?)
		case stateTokenMismatch(String, String)
		case issuingServerMismatch(String, String)
		case accessDenied
		case invalidScope
		case httpResponse(response: HTTPDataResponse)
		case oauthError(OAuth.ErrorResponse, HTTPResponse.Status)
		case subjectMismatch(actual: String?, expected: String)
		case notImplemented

		public var errorDescription: String? {
			switch self {
			case .missingScheme: "Missing scheme"
			case .missingIssuer:
				"Missing iss parameter when authorization server supports issuer identification"
			case .insecureScheme: "Insecure scheme"
			case .unrecognizedTokenType: "Unrecognized Token Type"
			case .missingAuthCode: "Missing authorization code"
			case .tokenInvalid: "Token response failed to validate with tokenValidator"
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
				"HTTP error with status code: \(response.response.status.code), response: \(response)"
			case .oauthError(let errorBody, let statusCode):
				"OAuth error with status code: \(statusCode),  body: \(errorBody)"
			case .subjectMismatch(
				let actual,
				let expected
			):
				"Subject mismatch, expected \(expected), actual: \(String(describing: actual))"
			case .notImplemented: "Not implemented"
			}
		}
	}
}
