##############Variables#################
$notificationFirst = 30
$notificationSecond = 14
$notificationThird = 7
$sendermailaddress = "IT@company.com"
$SMTPserver = "relay.company.com"
$DN = "DC=company,DC=com"
########################################

##############Function##################
function SendMail ($SMTPserver,$sendermailaddress,$usermailaddress,$mailSubject,$mailBody)
{
    $smtpServer = $SMTPserver
    $msg = new-object Net.Mail.MailMessage
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    $msg.From = $sendermailaddress
    $msg.To.Add($usermailaddress)
    $msg.Subject = $mailSubject
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
        $accountExpires = (Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties accountExpires).accountExpires
        if (($accountExpires -ne 9223372036854775807) -AND ($accountExpires -ne 0))
        {
            $accountExpiresDate = [datetime]::FromFileTime((Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties accountExpires).accountExpires)
            if ($user.accountexpirationdate -gt $expirydate)
            {
                $delta = ($expirydate - (Get-Date)).Days
                $comparionresults = (($delta -eq $notificationFirst) -OR ($delta -eq $notificationSecond) -OR ($delta -le $notificationThird)) -AND ($delta -ge 1)
                if ($comparionresults)            
                {            
                    $mailBody = "Hi " + $user.GivenName + ",`r`n`r`n"            
                    $mailBody += "Your password will expire in " + $delta + " day(s). To avoid getting locked out of your account, please be sure to update it before then.`r`n`r`nCurrently, there is no way to change your password if you are off the network, so feel free to contact us before the expiration date with a new password and we'll be happy to update it for you.`r`n`r`n"            
                    $mailBody += "`r`n`r`n-Your Friendly IT Department"
                    $usermailaddress = $user.mail
                    $mailSubject = "Your password will expire in $delta day(s)"
                    #SendMail $SMTPserver $sendermailaddress $usermailaddress $mailSubject $mailBody
                    SendMail $SMTPserver $sendermailaddress jeff.seto@hogarthww.com $mailSubject $mailBody
                }
            }
        }
    }
    else
    {
        if($passwordexpirydefaultdomainpolicy)
        {
            $pwdlastset = [datetime]::FromFileTime((Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties pwdLastSet).pwdLastSet)
            $expirydate = ($pwdlastset).AddDays($defaultdomainpolicyMaxPasswordAge)
            $accountExpires = (Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties accountExpires).accountExpires
            if (($accountExpires -ne 9223372036854775807) -AND ($accountExpires -ne 0))
            {
                $accountExpiresDate = [datetime]::FromFileTime((Get-ADUser -LDAPFilter "(&(samaccountname=$samaccountname))" -properties accountExpires).accountExpires)
                if ($accountExpiresDate -gt $expirydate)
                {
                        $delta = ($expirydate - (Get-Date)).Days
                        $comparionresults = (($delta -eq $notificationFirst) -OR ($delta -eq $notificationSecond) -OR ($delta -le $notificationThird)) -AND ($delta -ge 1)
                        if ($comparionresults)
                        {
                            $mailBody = "Hi " + $user.GivenName + ",`r`n`r`n"
                            $delta = ($expirydate - (Get-Date)).Days
                            $mailBody += "Your password will expire in " + $delta + " day(s). To avoid getting locked out of your account, please be sure to update it before then.`r`n`r`nCurrently, there is no way to change your password if you are off the network, so feel free to contact us before the expiration date with a new password and we'll be happy to update it for you.`r`n`r`n"
                            $mailBody += "`r`n`r`n-Your Friendly IT Department"
                            $usermailaddress = $user.mail
                            $mailSubject = "Your password will expire in $delta day(s)"
                            #SendMail $SMTPserver $sendermailaddress $usermailaddress $mailSubject $mailBody
                            SendMail $SMTPserver $sendermailaddress jeff.seto@hogarthww.com $mailSubject $mailBody
                        }
                }

            }
        }
    }
}