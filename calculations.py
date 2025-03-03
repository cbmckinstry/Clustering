import math

def singlevans(vans,singlecrews):
    if vans>=singlecrews:
        paired=0
        own=singlecrews
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

def optimalbus(k, L):
    count=0
    if k==0:
        return L
    if L==[]:
        L=[0]
        return L
    for j in L:
        if j%2!=0 and j>=3:
            count=count+1
    if count<=k:
        number=0
        for x in range(len(L)):
            if L[x]%2!=0 and L[x]>=3:
                L[x]=L[x]-3
                number=number+1
        b=k-number
        sixes=[j//6 for j in L]
        sumsixes=0
        for n in sixes:
            sumsixes=sumsixes+n
        threes=[n//3 for n in L]
        sumthrees=0
        for k in threes:
            sumthrees=sumthrees+k
        if b%2==0:
            while (sumsixes>0 and b>0):
                for x in range(len(L)):
                    if L[x]>=6 and (sumsixes>0 and b>1):
                        L[x]=L[x]-6
                        b=b-2
                        sumsixes=sumsixes-1
            while b>0 and sumthrees>0:
                for x in range(len(L)):
                    if L[x]>=3 and b>0 and sumthrees>0:
                        L[x]=L[x]-3
                        b=b-1
                        sumthrees=sumthrees-1
            return L
        else:
            for x in range(len(L)):
                if L[x]>=3:
                    L[x]=L[x]-3
                    break
            return optimalbus(b-1,L)

    else:
        index=-1
        kcounter=0
        for z in L:
            index=index+1
            if z%2!=0:
                kcounter=kcounter+1
            if kcounter==k:
                break
        for i in range(0,kcounter+1):
            if L[i]%2!=0:
                L[i]=L[i]-3
        return L


def cluster(singlesites,doublesites,triplesites,carclusters,vanclusters,buscapacities):
    listsum=0
    for i in buscapacities:
        listsum=listsum+i


    integer3list=[j//3 for j in buscapacities]
    triplesum=0
    for x in integer3list:
        triplesum=triplesum+x


    if buscapacities==[] or buscapacities==[0] or buscapacities==0:
        doublesum=0
    else:
        optimal=optimalbus(min(triplesites,triplesum),buscapacities)
        after3list=[k//2 for k in optimal]
        doublesum=0
        for a in after3list:
            doublesum=doublesum+a



    issue=carclusters+2*vanclusters+listsum-singlesites-2*doublesites-3*triplesites

    singlesInCars=0
    doublesInVans=0
    vanCarCombo=0
    singlesInVans=0
    doublesInCars=0
    triplesInBus=0
    doublesInBus=0
    singlesInBus=0
    triplesInCars=0
    triplesInVans=0



    triplesInBus=min(triplesites,triplesum)
    triplesAfterBus=triplesites-triplesInBus
    vanCarCombo=min(triplesAfterBus,vanclusters,carclusters)
    triplesAfterCombo=triplesites-triplesInBus-vanCarCombo
    carsAfterTriples=carclusters-vanCarCombo
    vansAfterTriples=vanclusters-vanCarCombo
    busSpace=listsum-3*triplesInBus
    if triplesAfterCombo>0 and (vanclusters-vanCarCombo)>0:
        triplesInVans=min(triplesAfterCombo,2*vansAfterTriples//3)
        vansAfterTriples=vansAfterTriples-3*triplesInVans//2
        triplesAfterCombo=triplesAfterCombo-triplesInVans
    elif triplesAfterCombo>0 and (carclusters-vanCarCombo)>0:
        triplesInCars=min(triplesAfterCombo,carsAfterTriples//3)
        carsAfterTriples=carsAfterTriples-3*triplesInCars
        triplesAfterCombo=triplesAfterCombo-triplesInCars

    doublesInVans=min(doublesites,math.floor(vansAfterTriples))
    doublesAfterVans=doublesites-doublesInVans
    doublesInBus=min(doublesAfterVans,doublesum)
    doublesAfterBus=doublesAfterVans-doublesInBus
    doublesInCars=min(carsAfterTriples,2*doublesAfterBus)//2
    doublesAfterCars=doublesAfterBus-doublesInCars
    busSpace=busSpace-2*doublesInBus

    carsAfterDoubles=carsAfterTriples-2*doublesInCars
    vansAfterDoubles=vansAfterTriples-doublesInVans
    singlesInCars=min(carsAfterDoubles,singlesites)
    singlesAfterCars=singlesites-singlesInCars
    singlesInVans=min(singlesAfterCars,vansAfterDoubles*2)
    singlesInBus=min(singlesAfterCars-singlesInVans,busSpace)

    carSurplus=carclusters-singlesInCars-vanCarCombo-2*doublesInCars-3*triplesInCars
    vanSurplus=vanclusters-doublesInVans-vanCarCombo-math.ceil((3*triplesInVans//2)+(singlesInVans//2))
    doublesInCars=doublesInCars+min(carSurplus//2,doublesInBus)
    carsPost=carSurplus-(2*min(carSurplus//2,doublesInBus))
    doublesInBus=doublesInBus-min(carSurplus//2,doublesInBus)

    vanCarCombo=vanCarCombo+min(carsPost,vanSurplus,triplesInBus)
    vansAfterOut=vanSurplus-min(carsPost,vanSurplus,triplesInBus)
    carsAfterOut=carsPost-min(carsPost,vanSurplus,triplesInBus)

    triplesLeftInBus=triplesInBus-min(carsPost,vanSurplus,triplesInBus)
    triplesInVans=triplesInVans+min(2*vansAfterOut//3,triplesLeftInBus)
    triplesLeftInBus=triplesLeftInBus-min(2*vansAfterOut//3,triplesLeftInBus)
    triplesInCars=triplesInCars+min(triplesLeftInBus,carsAfterOut//3)
    triplesInBus=min(triplesites-triplesInCars-vanCarCombo-triplesInVans,triplesum)

    VanList=triplesingle(vanclusters-doublesInVans-vanCarCombo,triplesInVans,singlesInVans)
    carsDone=carclusters-singlesInCars-vanCarCombo-2*doublesInCars-3*triplesInCars
    vansDone=2*vanclusters-2*doublesInVans-2*vanCarCombo-3*triplesInVans-singlesInVans

    busesDone=listsum-3*triplesInBus-2*doublesInBus-singlesInBus

    required=max(singlesites+2*doublesites+3*triplesites-carclusters-2*vanclusters,0)
    remain=[carsDone,vansDone,busesDone]

    finalList=[int(singlesInCars),int(doublesInVans),int(triplesInBus),int(doublesInCars),int(vanCarCombo),int(triplesInCars),int(singlesInBus),int(doublesInBus),VanList,required,remain,issue,abs(issue)]
    return finalList