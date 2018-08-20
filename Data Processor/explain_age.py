import random
import matplotlib.pyplot as plt

epoch = 100

age0to100 = list(range(0, 101))
labelChild =  [0 for i in range(0, 18)]
labelAdult = [1 for i in range(18, 101)]

combinedLabels = labelChild + labelAdult

dataset = list(zip(age0to100, combinedLabels))

# for (age, answer) in dataset:
#   print(str(age) + ' - ' + ('Adult' if answer == 1 else 'Child'))

ageOfAdulthood = random.randint(0, 101)

trainData = dataset[::2]
testData = dataset[1::2]

print('Initial Age of Adulthood: ' + str(ageOfAdulthood))

x_array = []
y_array = []

train_count = 0
for _ in range(epoch):
    for (age, answer) in trainData:
        if age < ageOfAdulthood and answer != 0:
            ageOfAdulthood -= 1
        elif age >= ageOfAdulthood and answer != 1:
            ageOfAdulthood += 1
        x_array.append(train_count)
        y_array.append(ageOfAdulthood)
        train_count += 1

print('Age of Adulthood After Training: ' + str(ageOfAdulthood))

correctCount = 0
for (age, answer) in testData:
    if age < ageOfAdulthood and answer == 0 or age >= ageOfAdulthood and answer == 1:
        correctCount += 1
    else:
        print('Incorrect! Age: ' + str(age) + ' - Answer: ' + str(answer) + ' but got: ' + str(int(not age < ageOfAdulthood)))

print('Accuracy: ' + '{:.2%}'.format(correctCount/len(testData)))

plt.plot(x_array, y_array, 'ro')
plt.show()