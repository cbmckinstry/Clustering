import math

def singlevans(vans,singlecrews):
    if vans>=singlecrews:
        paired=0
        own=singlecrews
    elif 2*vans<singlecrews:
        paired=2*vans
        own=0
    else:
        paired=2*(singlecrews-vans)
        own=singlecrews-paired
    return own,paired

def triplevans(vans,triplecrews):
    if vans>=2*triplecrews:
        own=triplecrews
        paired=0
    else:
        paired=4*triplecrews-2*vans
        own=triplecrews-paired
    return own,paired

def triplesingle(vans,triple,single):
    own,paired=triplevans(vans,triple)
    remainingVans=vans-2*own-(3*paired)//2
    if remainingVans>0:
        ind,pair=singlevans(remainingVans,single)
    else:
        ind,pair=0,0
    shared=single-ind-pair
    return [int(own),int(paired//2),int(ind),int(pair//2),int(shared)]

def cluster(singlesites,doublesites,triplesites,carclusters,vanclusters,buscapacities):

    busSpace=sum(buscapacities)
    initialVans=vanclusters

    required=max(singlesites+2*doublesites+3*triplesites-carclusters-2*vanclusters,0)
    issue=carclusters+2*vanclusters+busSpace-singlesites-2*doublesites-3*triplesites

    if busSpace!=0 and issue>=0:
        return [required]
    if issue<0:
        return [issue,abs(issue)]

    singlesInCars=0
    doublesInVans=0
    vanCarCombo=0
    singlesInVans=0
    doublesInCars=0
    triplesInCars=0
    triplesInVans=0

    vanCarCombo=min(triplesites,vanclusters,carclusters)            #Van and car combos for triples
    triplesites-=vanCarCombo
    carclusters-=vanCarCombo
    vanclusters-=vanCarCombo

    if triplesites>0 and (vanclusters-vanCarCombo)>0:
        triplesInVans=min(triplesites,2*vanclusters//3)
        vanclusters-=3*triplesInVans/2
        triplesites-=triplesInVans                              #Cannot do more van and car, so either vans or cars
    elif triplesites>0 and (carclusters-vanCarCombo)>0:
        triplesInCars=min(triplesites,carclusters//3)
        carclusters-=3*triplesInCars
        triplesites-=triplesInCars

    doublesInVans=min(doublesites,vanclusters)
    doublesites-=doublesInVans                          #Doubles in vans first
    vanclusters-=doublesInVans

    doublesInCars=min(carclusters,2*doublesites)//2
    doublesites-=doublesInCars                          #Doubles put into cars
    carclusters-=2*doublesInCars

    singlesInCars=min(carclusters,singlesites)      #Singles first in cars
    singlesites-=singlesInCars
    carclusters-=singlesInCars

    singlesInVans=min(singlesites,int(vanclusters*2))                #All singles will be placed
    singlesites-=singlesInVans
    vanclusters-=singlesInVans/2

    VanList=triplesingle(initialVans-doublesInVans-vanCarCombo,triplesInVans,singlesInVans)     #Calculates breakdown of vans

    remain=[carclusters,2*int(vanclusters)]
    finalList=[int(singlesInCars),int(doublesInVans),int(doublesInCars),int(vanCarCombo),int(triplesInCars),VanList,remain]
    return finalList