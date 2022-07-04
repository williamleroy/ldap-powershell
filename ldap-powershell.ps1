cls
$CSVFile = "C:\Scripts\ConfAD.csv"
$CSVData = Import-CSV -Path $CSVFile -Delimiter ";" -Encoding UTF8
#Importation du ficher csv qui contient la base de données de mes différents utilisateurs
$continue = $true
while ($continue){
  write-host "                 _____ _                             _ " -ForegroundColor Green
  write-host "                |  __ (_)                           | |" -ForegroundColor Green
  write-host "                | |__) |  ___ _ __ _ __ __ _ _ __ __| |" -ForegroundColor Green
  write-host "                |  ___/ |/ _ \ '__| '__/ _` | '__/ _` |" -ForegroundColor Green
  write-host "                | |   | |  __/ |  | | | (_| | | | (_| |" -ForegroundColor Green
  write-host "                |_|   |_|\___|_|  |_|  \__,_|_|  \__,_|" -ForegroundColor Green
  write-host “-------------------------------Active Directory-------------------------------” -ForegroundColor Gray
  write-host “   [1]" -NoNewline -ForegroundColor Yellow
  write-host " Créer un utilisateur avec son groupe et son dossier partagé dans l’ad” -ForegroundColor White
  write-host “   [2]" -NoNewline -ForegroundColor Yellow
  write-host " Exporter la liste des utilisateurs avec leurs informations" -ForegroundColor White
  write-host “   [3]" -NoNewline -ForegroundColor Yellow
  write-host " Arrêter un ordinateur à distance sur le réseau" -ForegroundColor White
  write-host “   [4]" -NoNewline -ForegroundColor Yellow
  write-host " Supprimer les dernières données entrées du fichier csv" -ForegroundColor White
  write-host “   [5]" -NoNewline -ForegroundColor Yellow
  write-host " EXIT" -ForegroundColor Red
  write-host "------------------------------------------------------------------------------" -ForegroundColor Gray
  $choix = read-host “  choix ”
  switch ($choix){
#Création d’un menu pour rendre plus facile la sélection des options
    1{
Foreach($Utilisateur in $CSVData){ 

$UtilisateurPrenom = $Utilisateur.Prenom
$UtilisateurNom = $Utilisateur.Nom
$UtilisateurLogin = ($UtilisateurPrenom).ToLower() + "_" + $UtilisateurNom.ToLower()
$UtilisateurEmail = "$UtilisateurLogin@pierrardincloud.be"
$UtilisateurMotDePasse = $Utilisateur.MotDePasse
$UtilisateurOU = $Utilisateur.OU
$UtilisateurGroupe1 = $Utilisateur.Annees
$UtilisateurGroupe2 = $Utilisateur.Ages
$UtilisateurDescription = " classe: " + $Utilisateur.Classe + ",Numéro de chambre: " + $Utilisateur.Numerodechambre + ",couloirs: " + $Utilisateur.Couloirs
#Initialisation des variables en fonction du fichier csv 
if (Get-ADUser -Filter {SamAccountName -eq $UtilisateurLogin})
    {
        Write-Warning "L'identifiant $UtilisateurLogin existe déja dans l'AD"
    }
else
    {
        New-ADUser -Name "$UtilisateurPrenom $UtilisateurNom" `
                   -DisplayName "$UtilisateurNom $UtilisateurPrenom" `
                   -GivenName "$UtilisateurPrenom" `
                   -SurName "$UtilisateurNom" `
                   -SamAccountName "$UtilisateurLogin" `
                   -UserPrincipalName "$UtilisateurLogin@internat.pie" `
                   -EmailAddress "$UtilisateurLogin@pierrardincloud.be" `
                   -Description "$UtilisateurDescription" `
                   -ProfilePath "\\WINSERINTERNAT\profils\$UtilisateurLogin" `
                   -Title "$UtilisateurNom $UtilisateurPrenom" `
                   -Path "OU=$UtilisateurOU,OU=OUinternat,DC=internat,DC=pie" `
                   -AccountPassword(ConvertTo-SecureString $UtilisateurMotDePasse -AsPlainText -Force) `
                   -ChangePasswordAtLogon $flase `
                   -CannotChangePassword $flase `
                   -Enabled $true

     Write-host "Création de l'utilisateur : $UtilisateurLogin ($UtilisateurNom $UtilisateurPrenom)" -ForegroundColor Green
#Création d’un utilisateur en fonction des différents paramètres définis
        if (-Not ($UtilisateurGroupe1 -eq ""))
        {
        Add-ADGroupMember -Identity $UtilisateurGroupe1 –Members $UtilisateurLogin
        write-host "$UtilisateurLogin à été ajouté dans le groupe un : $UtilisateurGroupe1" -ForegroundColor Green
        }
        if (-Not ($UtilisateurGroupe2 -eq ""))
        {
        Add-ADGroupMember -Identity $UtilisateurGroupe2 –Members $UtilisateurLogin
        write-host "$UtilisateurLogin à été ajouté dans le groupe deux : $UtilisateurGroupe2" -ForegroundColor Green
        }

        New-Item "E:\partage\$UtilisateurLogin" -itemType Directory

        New-SmbShare -Name "$UtilisateurLogin" -Path "E:\partage\$UtilisateurLogin" -FullAccess "$UtilisateurLogin"

        $acl = Get-Acl "E:\partage\$UtilisateurLogin"
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$UtilisateurLogin"," FullControl, Synchronize",3,0,"Allow")
        $acl.SetAccessRule($AccessRule)
        $acl | Set-Acl "E:\partage\$UtilisateurLogin"
#Création d'un dossier partagé avec des droits pour chaque utilisateur
    }
}
Start-Sleep -Seconds 3
cls
    }
    2{
$date = get-date -format "dd/MM/yyyy HH/mm"
$date = [string] $date
Get-ADUser -Filter * | Select-Object name,DisplayName,GivenName,SurName,SamAccountName,UserPrincipalName,EmailAddress,ProfilePath,Path | Export-Csv "C:\Users\Administrateur\Desktop\Userlog$date.csv" -Encoding UTF8
write-host "la création du fichier csv est sur votre bureau sous le nom :Userlog$date.csv" -ForegroundColor Green
Start-Sleep -Seconds 4
cls
#Exporter les infomations des utilisateurs dans un fichier csv
    }
3{
Get-ADComputer -Filter 'Name -like "PC_*"' -Properties IPv4Address | FT Name,IPv4Address -A
$StopComputer = read-host "enter le nom de l'ordinateur"
Stop-Computer -Force -ComputerName "$StopComputer"
Start-Sleep -Seconds 2
cls
#Option permettant d’éteindre un ordinateur à distance
}
4{
Foreach($Utilisateur in $CSVData){ 
$UtilisateurPrenom = $Utilisateur.Prenom
$UtilisateurNom = $Utilisateur.Nom
$UtilisateurLogin = ($UtilisateurPrenom).ToLower() + "_" + $UtilisateurNom.ToLower()
if (Get-ADUser -Filter {SamAccountName -eq $UtilisateurLogin})
    {
       Remove-ADUser -Identity "$UtilisateurLogin" -Confirm:$False
       Remove-Item -Path "E:\partage\$UtilisateurLogin" 
       Remove-SmbShare -Name "$UtilisateurLogin" -Confirm:$False
       write-host "suppression de $UtilisateurLogin et sont dossier personnel" -ForegroundColor Green
    }
else 
       {
       Write-Warning "les utilisateurs ont déja été supprimé"
       }
#Supprimer les dernières données entrées
                                    }
Start-Sleep -Seconds 2
cls
}
    5{$continue = $false}
    default {Write-Host "Choix invalide"-ForegroundColor Red}
#Vérification du menu si l’utilisateur a entré un caractère qui ne correspond pas dans le menu et action permettant de finir le scripte
           }
cls
Start-Sleep -Seconds 1
write-host "© Script AD DS for windows server 2022 By William" -ForegroundColor cyan
Start-Sleep -Seconds 1
cls
write-host "© Script AD DS for windows server 2022 By William" -ForegroundColor red
Start-Sleep -Seconds 1
cls
write-host "© Script AD DS for windows server 2022 By William" -ForegroundColor yellow
Start-Sleep -Seconds 1
cls
write-host "© Script AD DS for windows server 2022 By William" -ForegroundColor Green
Start-Sleep -Seconds 3
            }
