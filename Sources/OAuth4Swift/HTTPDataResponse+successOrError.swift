import GermConvenience
import HTTPTypes

extension HTTPDataResponse {
	func successOrThrow<E: Decodable>(
		decoding: E.Type,
		mapError: (E, HTTPResponse.Status) -> Error
	) throws {
		guard response.status.kind != .successful else { return }
		if let decoded = try? data.decode() as E {
			throw mapError(decoded, response.status)
		}
		throw HTTPResponseError.unsuccessful(response.status.code, data)
	}
}
