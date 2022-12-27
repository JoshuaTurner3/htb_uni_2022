# Catchy headliner :)

## The Challenge
In this challenge, the user connects to the server and is prompted with the following question:
```
What properties should your magic wand have?
```
Following this, the user can input any property in hex which is then added as a characteristic for a magic wand, this is reapeated three times. Should the user input repeated properties, then the program will prompt:
```
Only different properties are allowed!
```
and following this prompt will exit. A full example of a server interaction is as so:
```
What properties should your magic wand have?
Property: FF
7addf85ef83df437c4f7054a1fa2f042
Property: 0F
7fefc70a079f8966b9b6c25418d9265f
Property: FF
Only different properties are allowed!
```
## Overall Program Function
In order to better understand the function of the server, it is necessary to delve into the code behind its function.
```python
def main():
    aes = AESWCM(KEY)
    tags = []
    characteristics = []
    print("What properties should your magic wand have?")
    message = "Property: "

    counter = 0
    while counter < 3:
        characteristic = bytes.fromhex(input(message))
        if characteristic not in characteristics:
            characteristics.append(characteristic)

            characteristic_tag = aes.tag(message.encode() + characteristic, IV)
            tags.append(characteristic_tag)
            print(characteristic_tag)

            if len(tags) > len(set(tags)):
                print(FLAG)

            counter += 1
        else:
            print("Only different properties are allowed!")
            exit(1)
```
The program begins as observed above, with a prompt for a magic wand characteristic. Following this, 
### Blockify Function
### Pad Function
### Tag Function
### Encrypt Function
### Decrypt Function

## Encryption Analysis

## Conclusion
