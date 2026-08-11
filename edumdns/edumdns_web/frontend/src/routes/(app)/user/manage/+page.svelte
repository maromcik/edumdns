<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { errorMessage, sendForm } from '$lib/api';
	import type { UserManagePasswordTemplate, UserManageProfileTemplate } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const profileUser = $derived(template.user.user);

	// ---- Profile form ----
	let profileName = $state('');
	let profileSurname = $state('');
	let profileEmail = $state('');
	let profileMessage = $state<string | null>(null);
	let profileSuccess = $state(true);

	$effect.pre(() => {
		const u = data.template.user.user;
		profileName = u.name;
		profileSurname = u.surname;
		profileEmail = u.email;
	});

	async function updateProfile(event: SubmitEvent) {
		event.preventDefault();
		try {
			const res = await sendForm<UserManageProfileTemplate>('POST', '/user/manage', {
				email: profileEmail,
				name: profileName,
				surname: profileSurname
			});
			profileMessage = res.message;
			profileSuccess = res.success;
			await invalidateAll();
		} catch (err) {
			profileMessage = errorMessage(err);
			profileSuccess = false;
		}
	}

	// ---- Password form ----
	let showPassword = $state(false);
	let oldPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordMessage = $state<string | null>(null);
	let passwordSuccess = $state(true);

	async function updatePassword(event: SubmitEvent) {
		event.preventDefault();
		try {
			const res = await sendForm<UserManagePasswordTemplate>('POST', '/user/manage/password', {
				old_password: oldPassword,
				new_password: newPassword,
				confirm_password: confirmPassword
			});
			passwordMessage = res.message;
			passwordSuccess = res.success;
			if (res.success) {
				oldPassword = '';
				newPassword = '';
				confirmPassword = '';
			}
		} catch (err) {
			passwordMessage = errorMessage(err);
			passwordSuccess = false;
		}
	}
</script>

<svelte:head>
	<title>edumdns - Manage Profile</title>
</svelte:head>

<div id="profile-update-fields" class="max-w-5xl mx-auto">
	<div id="user-mgmt-profile-form">
		<div class="rounded-lg border border-base bg-cards p-6 mt-6">
			{#if template.oidc}
				<!-- OIDC mode: show user info only -->
				<div class="w-full">
					<h3 class="text-sat-xl mb-4">User Information</h3>
					<div class="space-y-2 w-full">
						<div class="grid grid-cols-2 border-b border-base pb-1">
							<span class="font-bold text-acc text-left">Name:</span>
							<span class="text-sat-xl text-right">{profileUser.name}</span>
						</div>
						<div class="grid grid-cols-2 border-b border-base pb-1">
							<span class="font-bold text-acc text-left">Surname:</span>
							<span class="text-sat-xl text-right">{profileUser.surname}</span>
						</div>
						<div class="grid grid-cols-2 pb-1">
							<span class="font-bold text-acc text-left">Email:</span>
							<span class="text-sat-xl text-right">{profileUser.email}</span>
						</div>
					</div>
				</div>
			{:else if showPassword}
				<div id="user-mgmt-password" class="w-full">
					<form class="p-5 flex flex-col items-center" onsubmit={updatePassword}>
						{#if passwordMessage}
							<button
								type="button"
								class="mb-3"
								class:text-success={passwordSuccess}
								class:text-error={!passwordSuccess}
								onclick={() => (passwordMessage = null)}
							>
								{passwordMessage}
							</button>
						{/if}
						<div class="justify-between w-full">
							<div class="flex flex-col space-y-2 w-full px-2">
								<input
									type="password"
									name="old_password"
									placeholder="Old Password"
									class="p-3 rounded border border-base text-forms-input"
									bind:value={oldPassword}
								/>
								<input
									type="password"
									name="new_password"
									placeholder="New Password"
									class="p-3 rounded border border-base text-forms-input"
									bind:value={newPassword}
								/>
								<input
									type="password"
									name="confirm_password"
									placeholder="Confirm New Password"
									class="p-3 rounded border border-base text-forms-input"
									bind:value={confirmPassword}
								/>
							</div>
						</div>

						<div class="flex m-2">
							<button
								type="button"
								onclick={() => (showPassword = false)}
								class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-forms font-medium text-acc hover:text-acc-xl mr-3 p-2 transition-colors"
							>
								←
							</button>
							<button type="submit" class="bg-acc rounded-md p-2 text-button text-md mr-2">
								Change Password
							</button>
						</div>
					</form>
				</div>
			{:else}
				<form
					class="flex flex-col w-full items-center mx-auto p-4 space-y-4"
					onsubmit={updateProfile}
				>
					{#if profileMessage}
						<button
							type="button"
							class="mb-3"
							class:text-success={profileSuccess}
							class:text-error={!profileSuccess}
							onclick={() => (profileMessage = null)}
						>
							{profileMessage}
						</button>
					{/if}

					<div class="flex flex-col w-full space-y-3 px-2">
						<div class="flex flex-col">
							<label for="profile-id-name" class="font-bold text-acc mb-1 text-left">Name</label>
							<input
								type="text"
								id="profile-id-name"
								name="name"
								placeholder="Name"
								class="p-3 rounded border border-base text-forms-input w-full"
								bind:value={profileName}
							/>
						</div>

						<div class="flex flex-col">
							<label for="profile-id-surname" class="font-bold text-acc mb-1 text-left"
								>Surname</label
							>
							<input
								type="text"
								id="profile-id-surname"
								name="surname"
								placeholder="Surname"
								class="p-3 rounded border border-base text-forms-input w-full"
								bind:value={profileSurname}
							/>
						</div>

						<div class="flex flex-col">
							<label for="profile-id-email" class="font-bold text-acc mb-1 text-left">Email</label>
							<input
								type="email"
								id="profile-id-email"
								name="email"
								placeholder="Email"
								class="p-3 rounded border border-base text-forms-input w-full"
								bind:value={profileEmail}
							/>
						</div>
					</div>

					<div class="flex gap-4 mt-4">
						<button type="submit" class="bg-acc rounded-md p-2 text-button text-md shadow-md">
							Update Profile
						</button>
						<button
							type="button"
							onclick={() => (showPassword = true)}
							class="bg-acc rounded-md p-2 text-button text-md shadow-md"
						>
							Change Password
						</button>
					</div>
				</form>
			{/if}
		</div>
	</div>
</div>
