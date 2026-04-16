//
//  ClientAuthInputs.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation
import GermConvenience
import HTTPTypes

extension OAuth {
	public struct ClientAuthInputs: Sendable {
		public let authServerMetadata: AuthServerMetadata
		public let parameters: FormParameters
		public let headers: HTTPFields
	}
}
