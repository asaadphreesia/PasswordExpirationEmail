##############Variables#################
$verbose = $false
$notificationFirst = 30
$notificationSecond = 14
$notificationThird = 7
$sendermailaddress = "IT@company.com"
$SMTPserver = "relay.company.com"
$DN = "DC=company,DC=com"
########################################

##############Function##################
function PreparePasswordPolicyMail ($ComplexityEnabled,$MaxPasswordAge,$MinPasswordAge,$MinPasswordLength,$PasswordHistoryCount)
{
    $verbosemailBody = "Below is a summary of the applied Password Policy settings:`r`n`r`n"
    $verbosemailBody += "Complexity Enabled = " + $ComplexityEnabled + "`r`n`r`n"
    $verbosemailBody += "Maximum Password Age = " + $MaxPasswordAge + "`r`n`r`n"
    $verbosemailBody += "Minimum Password Age = " + $MinPasswordAge + "`r`n`r`n"
    $verbosemailBody += "Minimum Password Length = " + $MinPasswordLength + "`r`n`r`n"
    $verbosemailBody += "Remembered Password History = " + $PasswordHistoryCount + "`r`n`r`n"
    return $verbosemailBody
}

function SendMail ($SMTPserver,$sendermailaddress,$usermailaddress,$mailBody)
{
    $smtpServer = $SMTPserver
    $msg = new-object Net.Mail.MailMessage
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    $msg.From = $sendermailaddress
    $msg.To.Add($usermailaddress)
    $msg.Subject = "Your password is about to expire"
    $msg.Body = $mailBody
    $smtp.Send($msg)
}
########################################

##############Main######################
$domainPolicy = Get-ADDefaultDomainPasswordPolicy
$passwordexpirydefaultdomainpolicy = $domainPolicy.MaxPasswordAge.Days -ne 0

if($passwordexpirydefaultdomainpolicy)
{            
    $defaultdomainpolicyMaxPasswordAge = $domainPolicy.MaxPasswordAge.Days
    if($verbose)
    {
        $defaultdomainpolicyverbosemailBody = PreparePasswordPolicyMail $PSOpolicy.ComplexityEnabled $PSOpolicy.MaxPasswordAge.Days $PSOpolicy.MinPasswordAge.Days $PSOpolicy.MinPasswordLength $PSOpolicy.PasswordHistoryCount
    }
}
            
foreach ($user in (Get-ADUser -SearchBase $DN -Filter * -properties mail))
{
    $samaccountname = $user.samaccountname
    $PSO= Get-ADUserResultantPasswordPolicy -Identity $samaccountname
    if ($PSO -ne $null)
    {
        $PSOpolicy = Get-ADUserResultantPasswordPolicy -Identity $samaccountname
        $PSOMaxPasswordAge = $PSOpolicy.MaxPasswordAge.days
        $pwdlastset = [datetime]::FromFileTime((Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties pwdLastSet).pwdLastSet)            
        $expirydate = ($pwdlastset).AddDays($PSOMaxPasswordAge)            
        $delta = ($expirydate - (Get-Date)).Days
        $comparionresults = (($delta -eq $notificationFirst) -OR ($delta -eq $notificationSecond) -OR ($delta -le $notificationThird)) -AND ($delta -ge 1)
        if ($comparionresults)            
        {            
            $mailBody = "Hi " + $user.GivenName + ",`r`n`r`n"            
            $mailBody += "Your password will expire in " + $delta + " day(s). To avoid getting locked out of your account, please be sure to update it before then.`r`n`r`nCurrently, there is no way to change your password if you are off the network, so feel free to contact us before the expiration date with a new password and we’ll be happy to update it for you.`r`n`r`n"            
            if ($verbose)            
            {            
                $mailBody += PreparePasswordPolicyMail $PSOpolicy.ComplexityEnabled $PSOpolicy.MaxPasswordAge.Days $PSOpolicy.MinPasswordAge.Days $PSOpolicy.MinPasswordLength $PSOpolicy.PasswordHistoryCount
            }
            $mailBody += "`r`n`r`n-Your Friendly IT Department"
            $usermailaddress = $user.mail
            SendMail $SMTPserver $sendermailaddress $usermailaddress $mailBody
        }
    }
    else
    {
        if($passwordexpirydefaultdomainpolicy)
        {
            $pwdlastset = [datetime]::FromFileTime((Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties pwdLastSet).pwdLastSet)
            $expirydate = ($pwdlastset).AddDays($defaultdomainpolicyMaxPasswordAge)
            $delta = ($expirydate - (Get-Date)).Days
            $comparionresults = (($delta -eq $notificationFirst) -OR ($delta -eq $notificationSecond) -OR ($delta -le $notificationThird)) -AND ($delta -ge 1)
            if ($comparionresults)
            {
                $mailBody = "Hi " + $user.GivenName + ",`r`n`r`n"
                $delta = ($expirydate - (Get-Date)).Days
                $mailBody += "Your password will expire in " + $delta + " day(s). To avoid getting locked out of your account, please be sure to update it before then.`r`n`r`nCurrently, there is no way to change your password if you are off the network, so feel free to contact us before the expiration date with a new password and we’ll be happy to update it for you.`r`n`r`n"
                if ($verbose)
                {
                    $mailBody += $defaultdomainpolicyverbosemailBody
                }
                $mailBody += "`r`n`r`n-Your Friendly IT Department"
                $usermailaddress = $user.mail
            SendMail $SMTPserver $sendermailaddress $usermailaddress $mailBody
            }

        }
    }
}