# Lucifen-Tools

Tools for anyone that is masochist enough to want to try work on a visual novel that is running on the Lucifen Engine.

# Scripts Usage
Currently the scripts uploaded here are for the Unpacking and Repacking of the LPK package files that the Visual novel files are in, all of these LPK files are encrypted with their own keys so you will need to go LPK-Keys.json and check up if the game you want to work with has their key published in already, these keys are needed not just for unpacking for repacking back the LPK files for their own Executable. 

Extracting:
> python lpk_extractor.py game.lpk --aux-key 0xDEADBEEF 0x01234567

> python lpk_extractor.py game.lpk --aux-key 1312048700 3034103149

Repacaking:
Change the Key values that I left here (from repacking Shuffle Essence) into the Key values of the VN you are working on.
> python lpk_repack.py PIC New_PIC.LPK --clone-from Original_PIC.LPK

## Elg Image encoding
Single file
> python elg2png.py original.elg new.png

> python png2elg.py edited.png new_edited.elg

batch folder → folder
> python png2elg.py PNG_in ELG_out

> python elg2png.py ELG_in PNG_out

## Key scanning
If you are working on a Lucifen based VN that doesn't have yet their keys found out you will need to dig out the key off the executable or maybe a script like the gameinit.sob sometimes, the scripts LPK seems to usually be using the generic LPK key in most VNs. 
> python lpk_keyfinder.py game.lpk --scan gameinit.sob navel03.sob

> python lpk_keyfinder.py game.lpk --scan game.exe --stride 1

> python lpk_keyfinder.py game.lpk --scan ./Scripts

### tune performance / sensitivity
> python lpk_keyfinder.py game.lpk --scan ./ --stride 4 --max-candidates 10 --max-read-bytes 33554432

### save the top hit into keys.json (lowercase basename key)
> python lpk_keyfinder.py game.lpk --scan gameinit.sob navel03.sob --out keys.json
