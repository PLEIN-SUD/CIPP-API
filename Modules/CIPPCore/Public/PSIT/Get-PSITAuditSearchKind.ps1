function Get-PSITAuditSearchKind {
    <#
    .SYNOPSIS
        The audit question each dossier type asks: record types and operations, per TypeId.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TypeId
    )

    switch ($TypeId) {
        4 {
            [pscustomobject]@{
                Key         = 'roles'
                Label       = 'changements de rôles'
                RecordTypes = @('azureActiveDirectory')
                Operations  = @('Add member to role.', 'Remove member from role.', 'Add eligible member to role.', 'Update role.')
            }
        }
        5 {
            [pscustomobject]@{
                Key         = 'mailbox-rules'
                Label       = 'règles de boîte'
                RecordTypes = @('exchangeAdmin', 'exchangeItem')
                Operations  = @('New-InboxRule', 'Set-InboxRule', 'Remove-InboxRule', 'Enable-InboxRule', 'Disable-InboxRule', 'UpdateInboxRules', 'Set-Mailbox')
            }
        }
        7 {
            [pscustomobject]@{
                Key         = 'mailbox-access'
                Label       = 'accès et délégations'
                RecordTypes = @('exchangeAdmin')
                Operations  = @('Add-MailboxPermission', 'Remove-MailboxPermission', 'Add-RecipientPermission', 'AddFolderPermissions', 'New-Mailbox', 'Set-Mailbox')
            }
        }
        default { $null }
    }
}
