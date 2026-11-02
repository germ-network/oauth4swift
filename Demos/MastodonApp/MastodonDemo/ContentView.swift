import SwiftUI

struct ContentView: View {
	@State private var state = AppState()

	var body: some View {
		NavigationStack {
			Group {
				if state.session != nil {
					LoggedInView(state: state)
				} else {
					LoginView(state: state)
				}
			}
			.navigationTitle("Mastodon OAuth Demo")
		}
		.task { await state.tryRestore() }
	}
}

struct LoginView: View {
	@Bindable var state: AppState

	var body: some View {
		Form {
			Section("Instance") {
				TextField("mastodon.social", text: $state.instanceDomain)
					.autocorrectionDisabled()
					#if os(iOS)
						.textInputAutocapitalization(.never)
						.keyboardType(.URL)
					#endif
			}

			if let error = state.errorMessage {
				Section {
					Text(error).foregroundStyle(.red)
				}
			}

			Section {
				Button {
					Task { await state.login() }
				} label: {
					Group {
						if state.isLoading {
							ProgressView()
						} else {
							Text("Log in with Mastodon")
						}
					}
					.frame(maxWidth: .infinity)
				}
				.disabled(state.isLoading || state.instanceDomain.isEmpty)
			}
		}
	}
}

struct LoggedInView: View {
	let state: AppState

	var body: some View {
		Form {
			if let info = state.userInfo {
				Section {
					HStack(spacing: 12) {
						if let picture = info.picture {
							AsyncImage(url: picture) { image in
								image.resizable().scaledToFill()
							} placeholder: {
								Color.secondary.opacity(0.2)
							}
							.frame(width: 48, height: 48)
							.clipShape(Circle())
						}
						VStack(alignment: .leading) {
							if let name = info.name {
								Text(name).font(.headline)
							}
							if let username = info.preferredUsername {
								Text("@\(username)").font(.subheadline).foregroundStyle(.secondary)
							}
						}
					}
				}
			}

			Section {
				Button(role: .destructive) {
					Task { await state.logout() }
				} label: {
					Text("Log out")
				}
			}
		}
	}
}
