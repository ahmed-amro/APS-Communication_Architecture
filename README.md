# APS_Communication_Architecture
A model for a communication architecture of an Autonomous Passenger Ship (APS). The architecture model is designed using the Architecture Analysis and Design Language (AADL) and includes the different architectural components with varying degrees of abstractions to provide flexibility in implementation options and to support various use cases of this technology. 

```diff
- Note: The latest architecture model migh not be reflected by the model shared in this repository. We will do out best to update the model here with latest desing improvmnets. Contact us if you are interested in unpublished updates. 
```

## Brief Description
The model is represented in a Top-down Component-based manner. Each high level component in the ecosystem is described in a separate AADL package (.aadl). 

### Ecosystem (Operational Context)
A package containing a wide view of all the high-level components called (Overall.aadl) can be a good place to start. In (Overall.aadl) all high-level components and their connections can be observed (See image below) and can be accessed further from there. 

A summary of all high-level components and their associated aadl package is mentioned below:

- Auto Passenger Ship (APS)    : APS.aadl
- Remote Control Center (RCC)  : RCC.aadl
- Cloud Component              : CloudComponent.aadl
- Emergency Control team       : ECT.aadl
- Mobile Communicaiton Network : Mobile5GNetwork.aadl
- Shore Sensor System          : SSS.aadl
- Other Ships                  : Ship.aadl
- Traffic Information Services : TIS.aadl
- Related Stakeholders         : Stakeholder.aadl
- Aids to Navigation Services  : AidsToNavigation.aadl

 ### Properties
Specific component-level requirements have been created to better descripe the components and to aid in the implementation phase. 
- AddedCommunicationProperties.aadl
- Requirements.aadl

## Acknowledgment 
This work is part of an ongoing project an the Norwegian University of Science and Technology (NTNU) called the Autoferry (https://www.ntnu.edu/autoferry). We here acknowledge all the support provided by the university and the help received from project members to create this architecture.  

## Contact us
Architect: Ahmed Amro, PhD in Cybersecurity (candidate)
Email: ahmed.amro@ntnu.no
