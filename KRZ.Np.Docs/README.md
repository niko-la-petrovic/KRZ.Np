# Docs

## Apply steganography

``` ps
.\KRZ.Np.Cli.exe -e -s G:\downloads\kripto_images_bmp\1.bmp -r -i "teaieaf"
```

## Decode steganography

``` ps
.\KRZ.Np.Cli.exe -e -s G:\downloads\kripto_images_bmp\1_modified.bmp -r
```

## Gen FreeQuestions

``` ps
1..10 | % -Begin { $rand = [System.Random]::new(); } -Process { $a = $rand.Next(0, 100); $b = $rand.Next(200, 400); $sum = $a+$b; "{ `"TypeDiscriminator`": `"FreeQuestion`", `"Text`": `"Koliko je $a + $b ?`", `"Answer`": `"$sum`" }" }
```

## Gen MultipleChoiceQuestions

``` ps
1..10 | % -Begin { $rand = [System.Random]::new(); } -Process { $a = $rand.Next(0, 100); $b = $rand.Next(200, 400); $sum = $a+$b; $choicesStr = (1..3 | % { "`"$($rand.Next(0, 1000))`"" } ); "{ `"TypeDiscriminator`": `"MultipleChoiceQuestion`", `"Text`": `"Koliko je $a + $b ?`", `"Answer`": `"$sum`", `"Choices`": [ `"$sum`", $([string]::Join(', ', $choicesStr)) ] }" }
```

## Encoding the questions

``` ps
$imageDir = "G:\downloads\kripto_images_bmp\"
$qJson = Get-Content .\questions.json -Raw | ConvertFrom-Json
$n = $qJson.Count
$images = gci $imageDir | Where-Object { -not $_.Name.Contains("modified") }
$qJson | % -Begin {$i = 0} -Process { $image = $images[$i]; .\KRZ.Np.Cli.exe -e -s ($image.FullName) -i ([regex]::Replace(($_ | ConvertTo-Json -Compress), '"', '\"')); $i++ }
```

## Decoding the questions

```ps
$modifiedImages = gci $imageDir | Where-Object { $_.Name.Contains("modified") }
$modifiedImages | % { .\KRZ.Np.Cli.exe -r -s ($_.FullName) }
```

## Root CA

```bash
BA
Republic of Srpska
Banja Luka
Company
Org Unit
Root CA
ca@ca.com
Root CA

root-ca
```

## CA1

```
BA
Republic of Srpska
Banja Luka
Company
Org Unit
CA1
ca1@ca.com
CA1

ca1
```

## User
```
y
Nikola Petrovic
123
BA
Republic of Srpska
Banja Luka
Company
Org Unit
Nikola Petrovic
np@ca.com
Nikola Petrovic

nikola-petrovic
```
