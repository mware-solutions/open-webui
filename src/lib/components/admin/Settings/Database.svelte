<script lang="ts">
	import fileSaver from 'file-saver';
	const { saveAs } = fileSaver;

	import { downloadDatabase, downloadLiteLLMConfig } from '$lib/apis/utils';
	import { onMount, getContext } from 'svelte';
	import { config, user } from '$lib/stores';
	import { toast } from 'svelte-sonner';
	import { getAllUserChats } from '$lib/apis/chats';
	import { getUserById, getUsers } from '$lib/apis/users';
	import { exportConfig, importConfig } from '$lib/apis/configs';
	import * as XLSX from 'xlsx';


	const i18n = getContext('i18n');

	export let saveHandler: Function;


    export const exportAllUserChats = async (format: 'json' | 'csv' | 'xlsx' = 'json') => {
    	const data = await getAllUserChats(localStorage.token);

    	if (!Array.isArray(data)) {
    		throw new Error('Invalid data format received');
    	}

    	let blob: Blob;
    	const filename = `all-chats-export-${Date.now()}.${format}`;

        const userInfoMap = new Map<string, { name: string; email: string }>();

    	if(format === 'csv' || format === 'xlsx'){
            const users = await getUsers(localStorage.token);

            try{
                users.forEach((u) => {
                	userInfoMap.set(u.id, {
                		name: u.name,
                		email: u.email
                	});
                });
            } catch(error){
                console.log("getUserById failed: ", error);
            }

    	}

    	if (format === 'json') {
    		blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    	} else if (format === 'csv') {
    	    try{
                const normalized = expandChatsForExport(data, userInfoMap);
                const worksheet = XLSX.utils.json_to_sheet(normalized);
                const csv = XLSX.utils.sheet_to_csv(worksheet);
                blob = new Blob([csv], { type: 'text/csv' });
            } catch(error){
                console.error("❌ CSV export failed:", error);
            }
    	} else if (format === 'xlsx') {
    	    const normalized = expandChatsForExport(data, userInfoMap);
    		const worksheet = XLSX.utils.json_to_sheet(normalized);
    		const workbook = XLSX.utils.book_new();
    		XLSX.utils.book_append_sheet(workbook, worksheet, 'Chats');
    		const xlsxBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'array' });
    		blob = new Blob([xlsxBuffer], {
    			type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    		});
    	} else {
    	    console.log("eroare")
    		throw new Error('Unsupported format');
    	}
    	saveAs(blob, filename);
    };
	onMount(async () => {
		// permissions = await getUserPermissions(localStorage.token);
	});
	let format = 'json';

	function expandChatsForExport(rawData: any[], userInfoMap: Map<string, { name: string; email: string }>): any[] {
    	const rows: any[] = [];

    	for (const item of rawData) {
    		const chat = item.chat || {};
    		const messages: any[] = chat.messages || [];
    		let lastUserMessage = '';

    		for (const msg of messages) {
    			if (msg.role === 'user') {
    				lastUserMessage = msg.content || '';
    			} else if (msg.role === 'assistant') {
    			    const userInfo = userInfoMap.get(item.user_id) || {};
    				rows.push({
    					user_id: item.user_id,
    					name: userInfo.name || '',
                        email: userInfo.email || '',
    					chat_title: chat.title || '',
    					model: chat.models?.[0] || '',
    					timestamp: formatTimestamp(msg.timestamp),
    					user_message: lastUserMessage,
    					assistant_reply: msg.content || ''
    				});
    				lastUserMessage = '';
    			}
    		}
    	}

    	return rows;
    }


    function formatTimestamp(ts: number): string {
        if (!ts) return '';
        if (ts > 1e12) {
            return new Date(ts).toLocaleString();
        } else {
            return new Date(ts * 1000).toLocaleString();
        }
    }

</script>

<form
	class="flex flex-col h-full justify-between space-y-3 text-sm"
	on:submit|preventDefault={async () => {
		saveHandler();
	}}
>
	<div class=" space-y-3 overflow-y-scroll scrollbar-hidden h-full">
		<div>
			<div class=" mb-2 text-sm font-medium">{$i18n.t('Database')}</div>

			<input
				id="config-json-input"
				hidden
				type="file"
				accept=".json"
				on:change={(e) => {
					const file = e.target.files[0];
					const reader = new FileReader();

					reader.onload = async (e) => {
						const res = await importConfig(localStorage.token, JSON.parse(e.target.result)).catch(
							(error) => {
								toast.error(error);
							}
						);

						if (res) {
							toast.success('Config imported successfully');
						}
						e.target.value = null;
					};

					reader.readAsText(file);
				}}
			/>

			<button
				type="button"
				class=" flex rounded-md py-2 px-3 w-full hover:bg-gray-200 dark:hover:bg-gray-800 transition"
				on:click={async () => {
					document.getElementById('config-json-input').click();
				}}
			>
				<div class=" self-center mr-3">
					<svg
						xmlns="http://www.w3.org/2000/svg"
						viewBox="0 0 16 16"
						fill="currentColor"
						class="w-4 h-4"
					>
						<path d="M2 3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3Z" />
						<path
							fill-rule="evenodd"
							d="M13 6H3v6a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V6ZM8.75 7.75a.75.75 0 0 0-1.5 0v2.69L6.03 9.22a.75.75 0 0 0-1.06 1.06l2.5 2.5a.75.75 0 0 0 1.06 0l2.5-2.5a.75.75 0 1 0-1.06-1.06l-1.22 1.22V7.75Z"
							clip-rule="evenodd"
						/>
					</svg>
				</div>
				<div class=" self-center text-sm font-medium">
					{$i18n.t('Import Config from JSON File')}
				</div>
			</button>

			<button
				type="button"
				class=" flex rounded-md py-2 px-3 w-full hover:bg-gray-200 dark:hover:bg-gray-800 transition"
				on:click={async () => {
					const config = await exportConfig(localStorage.token);
					const blob = new Blob([JSON.stringify(config)], {
						type: 'application/json'
					});
					saveAs(blob, `config-${Date.now()}.json`);
				}}
			>
				<div class=" self-center mr-3">
					<svg
						xmlns="http://www.w3.org/2000/svg"
						viewBox="0 0 16 16"
						fill="currentColor"
						class="w-4 h-4"
					>
						<path d="M2 3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3Z" />
						<path
							fill-rule="evenodd"
							d="M13 6H3v6a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V6ZM8.75 7.75a.75.75 0 0 0-1.5 0v2.69L6.03 9.22a.75.75 0 0 0-1.06 1.06l2.5 2.5a.75.75 0 0 0 1.06 0l2.5-2.5a.75.75 0 1 0-1.06-1.06l-1.22 1.22V7.75Z"
							clip-rule="evenodd"
						/>
					</svg>
				</div>
				<div class=" self-center text-sm font-medium">
					{$i18n.t('Export Config to JSON File')}
				</div>
			</button>

			<hr class=" dark:border-gray-850 my-1" />

			{#if $config?.features.enable_admin_export ?? true}
				<div class="  flex w-full justify-between">
					<!-- <div class=" self-center text-xs font-medium">{$i18n.t('Allow Chat Deletion')}</div> -->

					<button
						class=" flex rounded-md py-1.5 px-3 w-full hover:bg-gray-200 dark:hover:bg-gray-800 transition"
						type="button"
						on:click={() => {
							// exportAllUserChats();

							downloadDatabase(localStorage.token).catch((error) => {
								toast.error(error);
							});
						}}
					>
						<div class=" self-center mr-3">
							<svg
								xmlns="http://www.w3.org/2000/svg"
								viewBox="0 0 16 16"
								fill="currentColor"
								class="w-4 h-4"
							>
								<path d="M2 3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3Z" />
								<path
									fill-rule="evenodd"
									d="M13 6H3v6a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V6ZM8.75 7.75a.75.75 0 0 0-1.5 0v2.69L6.03 9.22a.75.75 0 0 0-1.06 1.06l2.5 2.5a.75.75 0 0 0 1.06 0l2.5-2.5a.75.75 0 1 0-1.06-1.06l-1.22 1.22V7.75Z"
									clip-rule="evenodd"
								/>
							</svg>
						</div>
						<div class=" self-center text-sm font-medium">{$i18n.t('Download Database')}</div>
					</button>
				</div>
                <div class="  flex w-full justify-between">
                    <button
                        class=" flex rounded-md py-2 px-3 w-full hover:bg-gray-200 dark:hover:bg-gray-800 transition"
                        on:click={() => {
                            exportAllUserChats(format);
                        }}
                    >
                        <div class=" self-center mr-3">
                            <svg
                                xmlns="http://www.w3.org/2000/svg"
                                viewBox="0 0 16 16"
                                fill="currentColor"
                                class="w-4 h-4"
                            >
                                <path d="M2 3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3Z" />
                                <path
                                    fill-rule="evenodd"
                                    d="M13 6H3v6a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V6ZM8.75 7.75a.75.75 0 0 0-1.5 0v2.69L6.03 9.22a.75.75 0 0 0-1.06 1.06l2.5 2.5a.75.75 0 0 0 1.06 0l2.5-2.5a.75.75 0 1 0-1.06-1.06l-1.22 1.22V7.75Z"
                                    clip-rule="evenodd"
                                />
                            </svg>
                        </div>
                        <div class=" self-center text-sm font-medium">
                            {$i18n.t('Export All Chats (All Users)')}
                        </div>
                    </button>
				    <select
                        bind:value={format}
                        class="rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-sm px-7 py-1"
                    >
                        <option value="json">JSON</option>
                        <option value="csv">CSV</option>
                        <option value="xlsx">Excel (.xlsx)</option>
                    </select>
                </div>
			{/if}
		</div>
	</div>

	<!-- <div class="flex justify-end pt-3 text-sm font-medium">
		<button
			class=" px-4 py-2 bg-emerald-700 hover:bg-emerald-800 text-gray-100 transition rounded-lg"
			type="submit"
		>
			{$i18n.t('Save')}
		</button>

	</div> -->
</form>
